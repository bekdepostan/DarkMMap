#include "MemCore.h"
#include <algorithm>

namespace ds_mmap
{
    namespace ds_process
    {
        CMemCore::CMemCore(void)
            : m_hProcess(NULL)
            , m_hMainThd(NULL)
            , m_pid(0)
            , m_hWorkThd(NULL)
            , m_hWaitEvent(NULL)
            , m_pWorkerCode(nullptr)
            , m_pCodecave(nullptr)
            , m_codeSize(0)
        {
        }

        CMemCore::~CMemCore(void)
        {
            TerminateWorkerThread();

            if(m_hProcess)
                CloseHandle(m_hProcess);

            if(m_hMainThd)
                CloseHandle(m_hMainThd);

            if(m_pCodecave)
                Free(m_pCodecave);

            FreeAll();
        }

        /*
            Allocate memory in process

            IN:
                size - amount to allocate in bytes
                pAddr - desired address of allocated memory

            OUT:
                pAddr - address of allocated memory

            RETURN:
                Error code
        */
        DWORD CMemCore::Allocate( size_t size, PVOID &pAddr )
        {
            SetLastError(ERROR_SUCCESS);

            void* pTmp = VirtualAllocEx(m_hProcess, pAddr, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if(!pTmp)
            {
                pTmp = VirtualAllocEx(m_hProcess, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                if(pTmp)
                {
                    pAddr = pTmp;
                    m_Allocations.emplace_back(pTmp);
                    SetLastError(ERROR_IMAGE_NOT_AT_BASE);
                }
            }
            else
            {
                pAddr = pTmp;
                m_Allocations.emplace_back(pAddr);            
            }

            return GetLastError();
        }

        /*
            Free allocated memory in process

            IN:
                pAddr - address to release

            OUT:
                void

            RETURN:
                Error code
        */
        DWORD CMemCore::Free( PVOID pAddr )
        {
            SetLastError(ERROR_SUCCESS);
            VirtualFreeEx(m_hProcess, pAddr, 0, MEM_RELEASE);

            //
            // Erase record from allocation table
            //
            auto iter = std::find(m_Allocations.begin(), m_Allocations.end(), pAddr);

            if(iter != m_Allocations.end())
                m_Allocations.erase(iter);

            return GetLastError();
        }

        /*
            Free all allocated memory regions
        */
        void CMemCore::FreeAll()
        {
            for(auto& pAddr : m_Allocations)
                VirtualFreeEx(m_hProcess, pAddr, 0, MEM_RELEASE);

            m_Allocations.clear();
        }


        /*
            Change memory protection

            IN:
                pAddr - address to change protection of
                size - size of data
                flProtect - new protection flags

            OUT:
                void

            RETURN:
                Error code
        */
        DWORD CMemCore::Protect( PVOID pAddr, size_t size, DWORD flProtect, DWORD *pOld /*= NULL*/ )
        {
            DWORD dwOld = 0;

            SetLastError(ERROR_SUCCESS);

            VirtualProtectEx(m_hProcess, pAddr, size, flProtect, &dwOld);

            if(pOld)
                *pOld = dwOld;

            return GetLastError();
        }

        /*
            Read process memory

            IN:
                dwAddress - read starting address
                dwSize - bytes to read
                pResult - pointer to receiving buffer

            OUT:
                pResult - read data

            RETURN:
                Error code
        */
        DWORD CMemCore::Read( void* dwAddress, size_t dwSize, PVOID pResult )
        {
            SIZE_T dwRead = 0;

            if(dwAddress == 0)
                return ERROR_INVALID_ADDRESS;

            if(!ReadProcessMemory(m_hProcess, (LPCVOID)dwAddress, pResult, dwSize, &dwRead) || dwRead != dwSize)
                return GetLastError();

            return ERROR_SUCCESS;
        }

        /*
            Write process memory

            IN:
                dwAddress - read starting address
                dwSize - bytes to read
                pResult - pointer to data to be written

            OUT:
                void

            RETURN:
                Error code
        */
        DWORD CMemCore::Write( void* pAddress, size_t dwSize, const void* pData )
        {
            SIZE_T dwWritten = 0;

            if(pAddress == NULL)
            {
                SetLastError(ERROR_INVALID_ADDRESS);
                return ERROR_INVALID_ADDRESS;
            }

            if(!WriteProcessMemory(m_hProcess, pAddress, pData, dwSize, &dwWritten) || dwWritten != dwSize)
                return GetLastError();

            return ERROR_SUCCESS;
        }

        /*
            Perform function call in remote process

            IN:
                pCodeCave - code to execute
                size - size of code
                pArg - argument to pass into function

            OUT:
                callResult - result of execution

            RETURN:
                Error code
        */
        DWORD CMemCore::RemoteCall( PVOID pCode, size_t size, size_t& callResult, PVOID pArg /*= NULL*/ )
        {
            // Allocate new codecave
            if(!m_pCodecave)
            {
                if(Allocate(size, m_pCodecave) != ERROR_SUCCESS)
                    return GetLastError();

                m_codeSize = size;
            }
            // Reallocate for new size
            else if(size > m_codeSize)
            {
                Free(m_pCodecave);
                m_pCodecave = nullptr;

                if(Allocate(size, m_pCodecave) != ERROR_SUCCESS)
                    return GetLastError();

                m_codeSize = size;
            }

            //Write code into process
            if(Write(m_pCodecave, size, pCode) != ERROR_SUCCESS)
                return GetLastError();
    
            return RemoteCallDirect(m_pCodecave, pArg, callResult);
        }


        /*
            Perform direct function call in remote process by its address

            IN:
                pProc - function address
                pArg - thread argument

            OUT:
                callResult - execution result

            RETURN:
                Error code
        */
        DWORD CMemCore::RemoteCallDirect( PVOID pProc, PVOID pArg, size_t& callResult, bool waitForReturn /*= true */ )
        {
            DWORD dwResult    = ERROR_SUCCESS;
            HANDLE hThread    = NULL;

            // Create execution thread
            callResult  = 0xFFFFFFF0;
            hThread     = CreateRemoteThread(m_hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pProc, pArg, 0, NULL);

            if (hThread && waitForReturn)
            {
                WaitForSingleObject(hThread, INFINITE);

                // TODO: Need to find something better for 64-bit results
                GetExitCodeThread(hThread, (LPDWORD)&callResult);
            }

            return dwResult;
        }

        /*
            Create thread for RPC

            RETURN:
                Thread ID
        */
        DWORD CMemCore::CreateWorkerThread()
        {
            AsmJit::Assembler a;
            AsmJitHelper ah(a);
            AsmJit::Label l_loop = a.newLabel();
            DWORD thdID = 0;
            int space   = 4 * WordSize;

            //
            // Create execution thread
            //
            if(!m_hWorkThd)
            {
                ah.GenPrologue();

                /*
                    for(;;)
                        SleepEx(5, TRUE);

                    ExitThread(SetEvent(m_hWaitEvent));
                */
                a.bind(l_loop);
                ah.GenCall(&SleepEx, { 5, TRUE });
                a.jmp(l_loop);

                ah.ExitThreadWithStatus();
                ah.GenEpilogue();

                // Write code into process
                if(Write((uint8_t*)m_pWorkerCode + space, a.getCodeSize(), a.make()) != ERROR_SUCCESS)
                {
                    if(m_pWorkerCode)
                    {
                        Free(m_pWorkerCode);
                        m_pWorkerCode = nullptr;
                    }

                    return 0;
                }

                m_hWorkThd = CreateRemoteThread(m_hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((uint8_t*)m_pWorkerCode + space), m_pWorkerCode, 0, &thdID);

                return thdID;
            }
            else
                return GetThreadId(m_hWorkThd);            
        }

        /*
            Create event to synchronize APC procedures

            RETURN:
                Error code
        */
        bool CMemCore::CreateAPCEvent( DWORD threadID )
        {         
            if(m_hWaitEvent == NULL)
            {
                AsmJit::Assembler a;
                AsmJitHelper ah(a);

                size_t dwResult        = ERROR_SUCCESS;
                void *pCodecave        = NULL;
                wchar_t pEventName[64] = {0};
                size_t len             =  sizeof(pEventName);

                // Generate event name
                swprintf_s(pEventName, ARRAYSIZE(pEventName), L"_MMapEvent_0x%x_0x%x", threadID, GetTickCount());

                Allocate(a.getCodeSize() + len, pCodecave);

                ah.GenPrologue();
                ah.GenCall(&CreateEventW, { NULL, TRUE, FALSE, (size_t)pCodecave });

                // Save event handle
            #ifdef _M_AMD64
                a.mov(AsmJit::ndx, AsmJit::qword_ptr(AsmJit::nsp, WordSize));
            #else
                a.mov(AsmJit::ndx, AsmJit::dword_ptr(AsmJit::nbp, 2 * WordSize));
            #endif   

                a.mov(sysint_ptr(AsmJit::ndx, WordSize), AsmJit::nax);

                ah.ExitThreadWithStatus();
                ah.GenEpilogue();

                if(Write((uint8_t*)pCodecave + len, a.getCodeSize(), a.make()) != ERROR_SUCCESS ||
                    Write((uint8_t*)pCodecave, len, pEventName) != ERROR_SUCCESS)
                {
                    if(pCodecave)
                        Free(pCodecave);

                    return false;
                }

                RemoteCallDirect((uint8_t*)pCodecave + len, m_pWorkerCode, dwResult);

                m_hWaitEvent = OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, pEventName);

                if(pCodecave)
                    Free(pCodecave);

                if(dwResult == NULL || m_hWaitEvent == NULL)
                {
                    SetLastError(ERROR_OBJECT_NOT_FOUND);
                    return false;
                }
            }

            return true;
        }

        /*
            Create environment for future RPC

            IN:
                noThread - create only codecave and sync event, without thread

            RETURN:
                Error code

            Code layout (x86/x64):
            -------------------------------------------------------------------------
            | Return value |  Event handle  |  Free Space   | Thread execution code |
            ------------------------------------------------------------------------
            |   4/8 bytes  |    4/8 bytes   |   8/16 bytes  |                       |
            -------------------------------------------------------------------------
        */
        DWORD CMemCore::CreateRPCEnvironment( bool noThread /*= false*/ )
        {
            DWORD dwResult = ERROR_SUCCESS;
            DWORD thdID    = 1337;
            bool status    = true;

            //
            // Allocate environment codecave
            //
            if(m_pWorkerCode == nullptr)
                Allocate(0x1000, m_pWorkerCode);

            // Create RPC thread
            if(noThread == false)
                thdID = CreateWorkerThread();

            // Create synchronization event
            status = CreateAPCEvent(thdID);
             
            if(thdID == 0 || status == false)
                dwResult = GetLastError();

            return dwResult;
        }

        /*
            Copy executable code to codecave for future execution

            IN:
                pCode - code to copy
                size - code size

            RETURN:
                Error code
        */
        DWORD CMemCore::PrepareCodecave( PVOID pCode, size_t size )
        {
            // Allocate new codecave
            if(!m_pCodecave)
            { 
                m_codeSize = (size > 0x1000) ? size : 0x1000;

                if(Allocate(m_codeSize, m_pCodecave) != ERROR_SUCCESS)
                {
                    m_codeSize = 0;
                    return GetLastError();
                }
            }

            // Reallocate for new size
            else if(size > m_codeSize)
            {
                Free(m_pCodecave);
                m_pCodecave = nullptr;

                if(Allocate(size, m_pCodecave) != ERROR_SUCCESS)
                    return GetLastError();

                m_codeSize = size;
            }

            if(Write(m_pCodecave, size, pCode) != ERROR_SUCCESS)
                return GetLastError();

            return ERROR_SUCCESS;
        }


        /*
            Terminate existing worker thread
    
            RETURN:
                Error code
        */
        DWORD CMemCore::TerminateWorkerThread()
        {
            if(m_hWaitEvent)
            {
                CloseHandle(m_hWaitEvent);
                m_hWaitEvent = NULL;
            }

            if(m_hWorkThd)
            {
                BOOL res   = TerminateThread(m_hWorkThd, 0);
                m_hWorkThd = NULL;

                if(m_pWorkerCode)
                {
                    Free(m_pWorkerCode);
                    m_pWorkerCode = nullptr;
                }

                return res == TRUE;
            }
            else
                return ERROR_SUCCESS;
        }

        /*
            Execute code in context of existing thread

            IN:
                pCode - code to execute
                size - code size

            OUT:
                callResult - last function result

            RETURN:
                Error code
        */
        DWORD CMemCore::ExecInWorkerThread( PVOID pCode, size_t size, size_t& callResult )
        {
            DWORD dwResult = ERROR_SUCCESS;

            // Write code
            dwResult = PrepareCodecave(pCode, size);
            if(dwResult != ERROR_SUCCESS)
                return dwResult;

            // Create thread if needed
            if(!m_hWorkThd)
                CreateRPCEnvironment();

            if(m_hWaitEvent)
                ResetEvent(m_hWaitEvent);

            // Execute code in thread context
            if(QueueUserAPC((PAPCFUNC)m_pCodecave, m_hWorkThd, (ULONG_PTR)m_pWorkerCode))
            {
                dwResult   = WaitForSingleObject(m_hWaitEvent, INFINITE);
                callResult = Read<size_t>(m_pWorkerCode);
            }

            // Ensure APC function fully returns
            Sleep(0);

            return dwResult;
        }

        /*
            Execute code in context of arbitrary existing thread
    
            IN:
                pCode - code to execute
                size - code size
                thread - handle of thread to execute code in
    
            OUT:
                callResult - last function result
    
            RETURN:
                Error code
            */
        DWORD CMemCore::ExecInAnyThread( PVOID pCode, size_t size, size_t& callResult, HANDLE hThread /*= NULL */ )
        {
            DWORD dwResult = ERROR_SUCCESS;
            CONTEXT ctx    = {0};

            if(hThread == NULL)
                hThread = m_hMainThd;

            // Write code
            dwResult = PrepareCodecave(pCode, size);
            if(dwResult != ERROR_SUCCESS)
                return dwResult;

            if(m_hWaitEvent)
                ResetEvent(m_hWaitEvent);

            SuspendThread(hThread);

            ctx.ContextFlags = CONTEXT_FULL;

            if(GetThreadContext(hThread, &ctx))
            {
                AsmJit::Assembler a;
                AsmJitHelper ah(a);

            #ifdef _M_AMD64
                const int count      = 15;
                AsmJit::GPReg regs[] = { AsmJit::rax, AsmJit::rbx, AsmJit::rcx, AsmJit::rdx, AsmJit::rsi, 
                                         AsmJit::rdi, AsmJit::r8,  AsmJit::r9,  AsmJit::r10, AsmJit::r11, 
                                         AsmJit::r12, AsmJit::r13, AsmJit::r14, AsmJit::r15, AsmJit::rbp };
                //
                // Preserve thread context
                // I don't care about FPU, XMM and anything else
                //
                a.sub(AsmJit::rsp, 15 * WordSize);  // Stack must be aligned on 16 bytes 
                a.pushfq();                            //

                for(int i = 0; i < count; i++)
                     a.mov(AsmJit::Mem(AsmJit::rsp, i * WordSize), regs[i]);

                ah.GenCall(m_pCodecave, { (size_t)m_pWorkerCode });

                for(int i = 0; i < count; i++)
                    a.mov(regs[i], AsmJit::Mem(AsmJit::rsp, i * WordSize));

                a.popfq();
                a.add(AsmJit::rsp, count * WordSize);

                a.jmp(ctx.Rip);
            #else
                a.pushad();
                a.pushfd();
                ah.GenCall(m_pCodecave, { (size_t)m_pWorkerCode });
                a.popfd();
                a.popad();
                a.push(ctx.Eip);
                a.ret();
            #endif
                
                if(Write((uint8_t*)m_pCodecave + size, a.getCodeSize(), a.make()) == ERROR_SUCCESS)
                {
                #ifdef _M_AMD64
                    ctx.Rip = (size_t)m_pCodecave + size;
                #else
                    ctx.Eip = (size_t)m_pCodecave + size;
                #endif

                    if(!SetThreadContext(hThread, &ctx))
                        dwResult = GetLastError();
                }
                else
                    dwResult = GetLastError();
            }
            else
                dwResult = GetLastError();

            ResumeThread(hThread);
            
            if(dwResult == ERROR_SUCCESS)
            {
                dwResult   = WaitForSingleObject(m_hWaitEvent, INFINITE);
                callResult = Read<size_t>(m_pWorkerCode);
            }

            return dwResult;
        }

        /*
            Find data by pattern

            IN:
                sig - byte signature to find
                pattern - pattern mask
                scanStart - scan start
                scanSize - size of data to scan

            OUT:
                out - found addresses

            RETURN:
                Number of found items

        */
        size_t CMemCore::FindPattern(const std::string& sig, uint8_t wildcard, void* scanStart, size_t scanSize, std::vector<size_t>& out)
        {
            out.clear();

            uint8_t *pBuffer = (uint8_t*)VirtualAlloc(NULL, scanSize, MEM_COMMIT, PAGE_READWRITE);

            const uint8_t* cstart = (const uint8_t*)pBuffer;
            const uint8_t* cend = cstart + scanSize;

            if (pBuffer && Read(scanStart, (DWORD)scanSize, pBuffer) == ERROR_SUCCESS)
            {
                for (;;)
                {
                    const uint8_t* res = std::search(cstart, cend, sig.begin(), sig.end(),
                        [&wildcard](uint8_t val1, uint8_t val2){ return (val1 == val2 || val2 == wildcard); });

                    if (res >= cend)
                        break;

                    out.emplace_back(res - pBuffer + (size_t)scanStart);

                    cstart = res + sig.length();
                }
            }

            if (pBuffer)
                VirtualFree(pBuffer, 0, MEM_DECOMMIT);

            return out.size();
        }

        size_t CMemCore::FindPattern(const std::string& sig, void* scanStart, size_t scanSize, std::vector<size_t>& out)
        {
            out.clear();

            uint8_t *pBuffer = (uint8_t*)VirtualAlloc(NULL, scanSize, MEM_COMMIT, PAGE_READWRITE);

            if (pBuffer && Read(scanStart, (DWORD)scanSize, pBuffer) == ERROR_SUCCESS)
            {
                size_t bad_char_skip[UCHAR_MAX + 1];

                const uint8_t* haystack = (const uint8_t*)pBuffer;
                const uint8_t* needle = (const uint8_t*)&sig[0];
                intptr_t       nlen = sig.length();
                intptr_t       scan = 0;
                intptr_t       last = nlen - 1;

                //
                // Preprocess
                //
                for (scan = 0; scan <= UCHAR_MAX; ++scan)
                    bad_char_skip[scan] = nlen;

                for (scan = 0; scan < last; ++scan)
                    bad_char_skip[needle[scan]] = last - scan;

                //
                // Search
                //
                while (scanSize >= (size_t)nlen)
                {
                    for (scan = last; haystack[scan] == needle[scan]; --scan)
                    if (scan == 0)
                        out.emplace_back(haystack - pBuffer + (size_t)scanStart);

                    scanSize -= bad_char_skip[haystack[last]];
                    haystack += bad_char_skip[haystack[last]];
                }
            }

            if (pBuffer)
                VirtualFree(pBuffer, 0, MEM_DECOMMIT);

            return out.size();
        }

        /*
            Retrieve process PEB address

            RETURN:
                PEB address
        */
        PPEB CMemCore::GetPebBase()
        {
            PROCESS_BASIC_INFORMATION pbi = {0};
            ULONG bytes = 0;

            NtQueryInformationProcess(m_hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &bytes);

            return pbi.PebBaseAddress;
        }

        /*
            Retrieve thread TEB address

            RETURN:
                TEB address
        */
        PTEB CMemCore::GetTebBase(HANDLE hThread /*= 0*/)
        {
            THREAD_BASIC_INFORMATION tbi = {0};    
            ULONG bytes = 0;

            if(hThread == NULL)
                hThread = m_hMainThd;

            NtQueryInformationThread(hThread, (THREADINFOCLASS)0, &tbi, sizeof(tbi), &bytes);

            return tbi.TebBaseAddress;
        }

    }
}