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
 *\brief Класс реализующий логику мьютекса
 *\details Для реализации используются виндовые мьютексы
 */
class Mutex
{
public:
	Mutex();
	~Mutex();

	/**
	 *\brief Функция блокировки мьютекса
	 *\param timeout максимальное время ожидания для блокировки
	 */
	void lock(DWORD timeout = INFINITE);

	/// Функция освобождения мьютекса
	void unlock();

protected:
	/// Идентификатор мьютекса
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
 *\brief Функция блокировки мьютекса
 * \param timeout максимальное время ожидания для блокировки
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

/// Функция освобождения мьютекса
void Mutex::unlock()
{
	::ReleaseMutex(mHandle);
}
/**
 *\brief Класс для управления работой с мьютексом
 * \details Класс гарантирует что захваченный мьютекс будет освобожден
 */
template< typename T >
class LockGuard
{
public:
	/**
	 *\brief Конструктор класса
	 *\param object объект который нужно блокировать и освобождать
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

	/// Освободить мьютекс досрочно
	void unlock()
	{
		if (is_locked)
		{
			mObject.unlock();
			is_locked = false;
		}
	}

protected:
	/// Объект которым нужно управлять
	T& mObject;
	/// Захвачен ли объект
	bool is_locked;
	LockGuard& operator=(const LockGuard&);
	LockGuard(const LockGuard&);
};


/**
 *\brief Класс реализации очереди запросов
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
 *\brief Класс реализации стопера
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
			//Не удалось положить запрос в очередь, очередь переполнилась, удаляем запрос
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
			//Не удалось положить запрос в очередь, очередь переполнилась, удаляем запрос
			DeleteRequest(request);
			return 0;
		}
	}

	return 0;
};


int main()
{
	const unsigned int CNT_THREADS = 4; //2 - принимающих запросы, 2 - обрабатывающих
	std::vector<HANDLE> threads(CNT_THREADS, NULL);
	//Создадим структуру с параментрами для функции в потоке
	std::unique_ptr<ThreadParams> params(new ThreadParams);
	for (int i = 0; i < CNT_THREADS; ++i)
	{
		//Создаем потоки
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


	//Ждем 30 секунд
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
		//Останавливаем выполнение операций
		params.get()->stopper.Stop();
	}

	//Запускаем работу
	if (::WaitForMultipleObjects(CNT_THREADS, threads.data(), TRUE, INFINITE) != WAIT_OBJECT_0)
	{
		std::cout << "WaitForMultipleObjects failed: " << ::GetLastError() << std::endl;
		return 0;
	}


	//Закроем хэндл таймера
	::CloseHandle(hTimer);

	//Закроем хэндлы
	for (auto &it : threads)
		::CloseHandle(it);

	std::cout << "Unprocessed requests count = " << params.get()->unprocessedRequests.Size() << std::endl;
	std::cout << "Processed requests count = " << params.get()->processedRequests.Size() << std::endl;

	//Удалим запросы
	while (auto request = params.get()->unprocessedRequests.Pop())
		DeleteRequest(request);

	while (auto request = params.get()->processedRequests.Pop())
		DeleteRequest(request);

	return 0;

}
