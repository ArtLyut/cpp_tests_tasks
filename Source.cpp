#define _WIN32_WINNT 0x502 
#include <iostream>
#include <Windows.h>
#include <queue>
#include <time.h>
#include <vector>
#include <string>
#include <iomanip>
#include <thread>


class Request
{

};

/**
 *\brief ����� ����������� ������ ��������
 *\details ��� ���������� ������������ �������� ��������
 */
class Mutex
{
public:
	Mutex();
	~Mutex();

	/**
	 *\brief ������� ���������� ��������
	 *\param timeout ������������ ����� �������� ��� ����������
	 */
	void lock(DWORD timeout = INFINITE);

	/// ������� ������������ ��������
	void unlock();

protected:
	/// ������������� ��������
	HANDLE mHandle;
};


Mutex::Mutex()
	: mHandle(::CreateMutex(NULL, FALSE, NULL))
{
}

Mutex::~Mutex()
{
	CloseHandle(mHandle);
}

/**
 *\brief ������� ���������� ��������
 * \param timeout ������������ ����� �������� ��� ����������
 */
void Mutex::lock(DWORD timeout)
{
	switch (::WaitForSingleObject(mHandle, timeout))
	{
	case WAIT_TIMEOUT:
	{
		throw std::runtime_error("Mutex timeout.");
		break;
	}
	case WAIT_ABANDONED:
	{
		throw std::runtime_error("Mutex lock error.");
	}
	case WAIT_OBJECT_0:
	{
		return;
	}
	case WAIT_FAILED:
	{
		// DWORD err_code = ::GetLastError();
		throw std::runtime_error("Mutex lock error.");
		break;
	}
	default:
		throw std::runtime_error("Undefined result of WaitForSingleObject(...)");
	}
}

/// ������� ������������ ��������
void Mutex::unlock()
{
	::ReleaseMutex(mHandle);
}
/**
 *\brief ����� ��� ���������� ������� � ���������
 * \details ����� ����������� ��� ����������� ������� ����� ����������
 */
template< typename T >
class LockGuard
{
public:
	/**
	 *\brief ����������� ������
	 *\param object ������ ������� ����� ����������� � �����������
	 */
	LockGuard(T& object)
		: mObject(object), is_locked(true)
	{
		mObject.lock();
	}

	~LockGuard()
	{
		if (is_locked)
			mObject.unlock();
	}

	/// ���������� ������� ��������
	void unlock()
	{
		if (is_locked)
		{
			mObject.unlock();
			is_locked = false;
		}
	}

protected:
	/// ������ ������� ����� ���������
	T& mObject;
	/// �������� �� ������
	bool is_locked;
	LockGuard& operator=(const LockGuard&);
	LockGuard(const LockGuard&);
};


/**
 *\brief ����� ���������� ������� ��������
 */
class RequestsQueue
{
private:
	std::queue<Request*> mQueue;
	Mutex mMutex;
public:
	RequestsQueue()
	{
	}

	void Push(Request* rec);

	Request* Pop();

	size_t Size();
};


void RequestsQueue::Push(Request* rec)
{
	LockGuard<Mutex> locker(mMutex);
	mQueue.push(rec);

}

Request* RequestsQueue::Pop()
{
	Request* val = nullptr;
	LockGuard<Mutex> locker(mMutex);
	if (!mQueue.empty())
	{
		val = mQueue.front();
		mQueue.pop();
	}
	return val;
}

size_t RequestsQueue::Size()
{
	size_t return_val;
	LockGuard<Mutex> locker(mMutex);
	return_val = mQueue.size();
	return return_val;
}

/**
 *\brief ����� ���������� �������
 */
class Stopper
{
private:
	volatile LONG mStopSignal{ 0 };
public:
	void Stop()
	{
		InterlockedExchange(&mStopSignal, 1);
	}
	bool StopSignal() const
	{
		return mStopSignal == 1;
	}
};

Request* GetRequest(Stopper stopSignal)
{
	const int EMULATE_WORKING_TIME = 1000;
	srand(time(NULL));
	int workingTime = rand() % EMULATE_WORKING_TIME + 1;
	Sleep(workingTime);

	return stopSignal.StopSignal() ? nullptr : (new Request());
};


void ProcessRequest(Request* request, Stopper stopSignal)
{
	if (stopSignal.StopSignal())
		return;

	const int EMULATE_WORKING_TIME = 1000;
	srand(time(NULL));
	int workingTime = rand() % EMULATE_WORKING_TIME + 1;
	Sleep(workingTime);
};

void DeleteRequest(Request* request)
{
	if (request == nullptr)
		return;
	delete request;
}

struct ThreadParams
{
	RequestsQueue unprocessedRequests;
	RequestsQueue processedRequests;
	Stopper stopper;
};

DWORD WINAPI consumerThread(LPVOID lpParams)
{
	Stopper& stopper = static_cast<ThreadParams*>(lpParams)->stopper;
	RequestsQueue& unprocessedRequests = static_cast<ThreadParams*>(lpParams)->unprocessedRequests;
	RequestsQueue& processedRequests = static_cast<ThreadParams*>(lpParams)->processedRequests;
	while (!stopper.StopSignal())
	{
		Request* request = unprocessedRequests.Pop();
		if (!request)
			continue;

		ProcessRequest(request, stopper);
		try
		{
			processedRequests.Push(request);
		}
		catch (const std::bad_alloc& ex)
		{
			//�� ������� �������� ������ � �������, ������� �������������, ������� ������
			DeleteRequest(request);
			return 0;
		}
	}

	return 0;
};

DWORD WINAPI producerThread(LPVOID lpParams)
{
	Stopper& stopper = static_cast<ThreadParams*>(lpParams)->stopper;
	RequestsQueue& unprocessedRequests = static_cast<ThreadParams*>(lpParams)->unprocessedRequests;

	while (!stopper.StopSignal())
	{
		Request* request = GetRequest(stopper);
		if (!request)
			continue;

		try
		{
			unprocessedRequests.Push(request);
		}
		catch (const std::bad_alloc& ex)
		{
			//�� ������� �������� ������ � �������, ������� �������������, ������� ������
			DeleteRequest(request);
			return 0;
		}
	}

	return 0;
};


int main()
{
	const unsigned int CNT_THREADS = 4; //2 - ����������� �������, 2 - ��������������
	std::vector<HANDLE> threads(CNT_THREADS, NULL);
	//�������� ��������� � ������������ ��� ������� � ������
	std::unique_ptr<ThreadParams> params(new ThreadParams);
	for (int i = 0; i < CNT_THREADS; ++i)
	{
		//������� ������
		threads[i] = i % 2 ? CreateThread(NULL, 0, producerThread, params.get(), 0, NULL) :
			CreateThread(NULL, 0, consumerThread, params.get(), 0, NULL);

		if (threads[i] == NULL)
		{
			std::cout << "ERROR: CreateThread failed!" << ::GetLastError() << std::endl;
			return 1;
		}
	}

	HANDLE hTimer = NULL;
	LARGE_INTEGER liDueTime;

	liDueTime.QuadPart = -10000000LL * 30;

	hTimer = CreateWaitableTimer(NULL, TRUE, NULL);
	if (NULL == hTimer)
	{
		std::cout << "CreateWaitableTimer failed: " << ::GetLastError() << std::endl;
		return 1;
	}


	//���� 30 ������
	if (!SetWaitableTimer(hTimer, &liDueTime, 0, NULL, NULL, 0))
	{
		std::cout << "SetWaitableTimer failed: " << ::GetLastError() << std::endl;
		return 2;
	}

	if (WaitForSingleObject(hTimer, INFINITE) != WAIT_OBJECT_0)
	{
		std::cout << "WaitForSingleObject failed: " << ::GetLastError() << std::endl;
		return 2;
	}
	else
	{
		//������������� ���������� ��������
		params.get()->stopper.Stop();
	}

	//��������� ������
	if (::WaitForMultipleObjects(CNT_THREADS, threads.data(), TRUE, INFINITE) != WAIT_OBJECT_0)
	{
		std::cout << "WaitForMultipleObjects failed: " << ::GetLastError() << std::endl;
		return 0;
	}


	//������� ����� �������
	::CloseHandle(hTimer);

	//������� ������
	for (auto &it : threads)
		::CloseHandle(it);

	std::cout << "Unprocessed requests count = " << params.get()->unprocessedRequests.Size() << std::endl;
	std::cout << "Processed requests count = " << params.get()->processedRequests.Size() << std::endl;

	//������ �������
	while (auto request = params.get()->unprocessedRequests.Pop())
		DeleteRequest(request);

	while (auto request = params.get()->processedRequests.Pop())
		DeleteRequest(request);

	return 0;

}
