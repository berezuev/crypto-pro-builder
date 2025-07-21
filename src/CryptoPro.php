<?php 

namespace CryptoProBuilder;

use BadMethodCallException;
use InvalidArgumentException;
use RuntimeException;
use FluentConsole\ConsoleRunner; // Убедитесь, что это правильный путь к вашему ConsoleRunner

class CryptoPro
{
    /**
     * @var ConsoleRunner Инстанс ConsoleRunner для выполнения команд.
     */
    protected ConsoleRunner $csp;

    /**
     * @var array Коллекция предопределенных паттернов для парсинга вывода команд.
     */
    protected array $patterns = [
        'containerFullPath' => '#\\\\.*#', // Возвращает полный путь контейнера
        'containerNameOnly' => '#\\\\([^\\\\]+)$#', // Возвращает только имя
        'hashformat' => '/^[A-Fa-f0-9]{64,128}$/', // Формат хэша (для ГОСТ Р 34.11-2012 это 64 или 128 символов)
        'hashFile' => [
            'fields' => ['hash'],
            'patterns' => [
                '/([A-F0-9]+)/i', // Возвращает hash подписанного файла
            ]
        ],
        'verifyHash' => [
            'fields' => ['status'],
            'patterns' => [
                '/File .* has been verified/i', // OK
                '/File .* was corrupted/i', // FAIL
            ]
        ],
        'signatureOwner' => '/Автор подписи:\s*(.*)/u', // Возвращает данные подписанта
        'certificatesCNOnly' => '/^Субъект\s*:\s.*?\bCN=([^,]+)/u', // Возвращает данные владельца сертификата по CN
        'certificates' => [
            'fields' => [
                'subject',
                'serialNumber',
                'sha1',
                'issued',
                'expires',
            ],
            'patterns' => [
                '/Субъект\s+:\s+.*CN=([^,]+)/u',
                '/Серийный номер\s+:\s+(.+)/',
                '/SHA1 отпечаток\s+:\s+([a-f0-9]+)/i',
                '/Выдан\s+:\s+(.+)/',
                '/Истекает\s+:\s+(.+)/',
            ]
        ]
    ];

    /**
     * @var array|null Текущий активный паттерн(ы) для парсинга вывода.
     */
    protected ?array $pattern = null;

    /**
     * @var array|null Ожидаемые поля для структурированного вывода.
     */
    protected ?array $expectedFields = null;

    /**
     * @var bool Флаг, указывающий, нужно ли структурировать выходные данные.
     */
    protected bool $structureMatches = false;

    /**
     * Конструктор класса CryptoProBuilder.
     * Инициализирует ConsoleRunner с указанной командой.
     *
     * @param string $command Путь к исполняемому файлу (например, 'csptest', 'cryptcp').
     * По умолчанию 'csptest', если он прописан в PATH.
     */
    public function __construct(string $command = 'csptest')
    {
        $this->csp = new ConsoleRunner();
        $this->csp->setCommand($command); // csptest должно быть прописано в окружении, иначе полный путь
    }

    /**
     * @var array Массив доступных команд/методов, которые могут быть вызваны динамически.
     */
    protected array $methods = [
        // Глобальные опции
        'help' => true,            // Печатает справку по программе
        'notime' => true,          // Не отображать время выполнения

        // Команды, специфичные для режима
        'lowenc' => true,          // Тестирование низкоуровневого шифрования/дешифрования
        'sfenc' => true,           // Упрощенное шифрование/дешифрование сообщений
        'lowsign' => true,         // Тестирование низкоуровневого подписания сообщений
        'sfsign' => true,          // Упрощенное подписание/проверка подписей сообщений
        'cmssfsign' => true,       // Упрощенное подписания/проверка подписей сообщений (устарело)
        'ipsec' => true,           // Тесты IPSec
        'defprov' => true,         // Манипуляции с дефолтным провайдером
        'property' => true,        // Получение/установка свойств сертификата для секретного ключа
        'mk' => true,              // Инициализация получения хэша (или вычисление хэша файла в Cpverify)
        'hash' => true,            // Получение хеша файла (или посчитать хэши файлов в cryptcp)
        'alg' => true,             // Установить хэш-алгоритм (или алгоритм хэширования в Cpverify)
        'certkey' => true,         // Изменить имя провайдера в сертификате секретного ключа
        'absorb' => true,          // Поглощение всех сертификатов из контейнеров с секретным ключом
        'tlss' => true,            // Запуск TLS сервера
        'tlsc' => true,            // Запуск TLS клиента
        'certlic' => true,         // Информация о лицензии сертификата
        'rc' => true,              // Проверка подписи PKCS#10/сертификата
        'minica' => true,          // Тест выпуска сертификатов
        'certprop' => true,        // Показать свойства сертификата
        'sfse' => true,            // Упрощенное тестирование SignedAndEnveloped сообщений
        'oid' => true,             // Получение/установка информации об OID
        'change' => true,          // Изменить пароль
        'passwd' => true,          // Установить или изменить пароль
        'keycopy' => true,         // Копирование контейнера
        'keyset' => true,          // Создать или открыть ключевой контейнер
        'card' => true,            // Информация о считывателях карт
        'enum' => true,            // Перечисление параметров CSP
        'perf' => true,            // Производственные тесты
        'speed' => true,           // Тесты скорости и установка оптимальной маски функции

        // Дополнительные команды:
        'ask' => true,             // Получить контекст csp с помощью моего сертификата (по умолчанию: нет)
        'in' => true,              // Входной файл
        'out' => true,             // Выходной файл
        'add' => true,             // Добавить сертификат
        'attached' => true,        // Встроенная подпись
        'detached' => true,        // Отсоединенная подпись
        'base64' => true,          // Ввод/вывод с преобразованием base64<->DER
        'addsigtime' => true,      // Добавить атрибут времени подписи
        'cades_strict' => true,    // Строгая генерация атрибута signingCertificateV2
        'cades_disable' => true,   // Отключить генерацию атрибута signingCertificateV2
        'display_content' => true, // Данные, которые должны отображаться на носителе/считывателе, встроены в содержимое сообщения
        'sign' => true,            // Подписать сообщение (или создать подписанное сообщение в cryptcp)
        'my' => true,              // Сертификат текущего пользователя
        'MY' => true,              // Сертификат локальной машины
        'CERT' => true,            // Часть имени поля Common Name или отпечаток сертификата
        'provname' => true,        // Имя провайдера (или имя криптопровайдера в Cpverify/cryptcp)
        'provtype' => true,        // Тип провайдера (или тип криптопровайдера в Cpverify/cryptcp)
        'cont' => true,            // Путь к контейнеру (или имя контейнера в Cpverify/cryptcp)
        'machinekeys' => true,     // Ключи на локальной машине
        'enum_cont' => true,       // Перечислить контейнеры
        'verifycontext' => true,   // Открытый контекст только для проверки
        'fqcn' => true,            // Отобразить полное имя контейнера
        'check' => true,           // Проверить контейнер
        'password' => true,        // Указать пароль
        'deletekeyset' => true,    // Удалить контейнер
        'container' => true,       // Имя контейнера
        'contsrc' => true,         // Имя исходного контейнера (весь путь)
        'contdest' => true,        // Имя конечного контейнера (весь путь)
        'verify' => true,          // Проверить файл с подписью (или проверить подпись сообщения/файла в cryptcp/Cpverify)
        'pinsrc' => true,          // Пароль исходного контейнера
        'pindest' => true,         // Пароль конечного контейнера
        'silent' => true,          // Не отображать пользовательский интерфейс
        'req_compliant' => true,   // Предварительный просмотр файла перед подписью/проверкой и проверка цепочки сертификатов (работает только с опцией '-detached')
        'list' => true,            // Получить список сертификатов
        'store' => true,           // Выбрать хранилище сертификатов

        // КриптоПро 5 версии (общие команды)
        'tls1_2' => true,          // Использование TLS 1.2
        'tls1_3' => true,          // Использование TLS 1.3
        'ecdsa' => true,           // Подпись с использованием алгоритма ECDSA
        'aes' => true,             // Шифрование с использованием алгоритма AES
        'rsa' => true,             // Шифрование с использованием алгоритма RSA
        'ocsp' => true,            // Проверка статуса сертификата через OCSP
        'csr' => true,             // Генерация запроса на сертификат (CSR)
        'pkcs12' => true,          // Создание файла PKCS#12
        'pkcs7' => true,           // Создание или проверка PKCS#7 подписи
        'signfile' => true,        // Подписать файл с помощью приватного ключа
        'verifyfile' => true,      // Проверка файла на наличие подписи
        'p12import' => true,       // Импорт PKCS#12 сертификатов
        'importkey' => true,       // Импорт приватного ключа
        'exportkey' => true,       // Экспорт приватного ключа
        'setprov' => true,         // Установить провайдер криптографии
        'getprov' => true,         // Получить информацию о текущем провайдере
        'backup' => true,          // Резервное копирование ключей
        'restore' => true,         // Восстановление ключей
        'log' => true,             // Записать лог операций
        'audit' => true,           // Аудит криптографических операций
        'timecheck' => true,       // Проверка времени подписания
        'signtime' => true,        // Время подписи
        'revoke' => true,          // Отозвать сертификат
        'expiry' => true,          // Проверка срока действия сертификата
        'validate' => true,        // Проверить корректность сертификата

        // Cpverify команды
        'logfile' => true,             // Путь к файлу лога (заменяет вывод в stdout/stderr)
        'sleep' => true,               // Пауза перед началом выполнения (в миллисекундах)
        'wnd' => true,                 // Показать окно с сообщением (MessageBox)
        'errwnd' => true,              // Показать MessageBox только при ошибке
        // 'mk' => true,               // Дублируется выше, сохранено как первое описание
        // 'verify' => true,           // Дублируется выше, сохранено как первое описание
        'rm' => true,                  // Вычисление хэшей для файлов из реестра
        'addreg' => true,              // Сохранить хэш файла в реестре
        'delreg' => true,              // Удалить хэш файла из реестра
        'rv' => true,                  // Проверка файлов из реестра
        'xm' => true,                  // Вычисление хэшей и сохранение в XML
        'xv' => true,                  // Проверка целостности по XML
        'x2r' => true,                 // Копирование хэшей из XML в реестр
        'r2x' => true,                 // Копирование хэшей из реестра в XML
        'file_sign' => true,           // Подпись файла с использованием контейнера
        'file_verify' => true,         // Проверка подписи файла
        // 'alg' => true,              // Дублируется выше, сохранено как первое описание
        'inverted_halfbytes' => true,  // Реверс половинок байтов хэша (0 или 1)
        // 'cont' => true,             // Дублируется выше, сохранено как первое описание
        'pin' => true,                 // Пароль к контейнеру
        // 'provname' => true,         // Дублируется выше, сохранено как первое описание
        // 'provtype' => true,         // Дублируется выше, сохранено как первое описание
        'timestamp' => true,           // Дата подписи в формате dd.mm.yyyy
        'filename' => true,            // Имя основного файла для подписи/проверки/хэширования
        'hashvalue' => true,           // Явно указанный хэш (если не использовать .hsh)
        'signval' => true,             // Значение подписи (если не использовать .sgn)
        'catname' => true,             // Имя каталога (для групповых операций)
        'in_file' => true,             // Входной XML-файл
        'out_file' => true,            // Выходной XML-файл

        // Методы CryptCP (добавлены без дубликатов)
        'encr' => true,            // cryptcp: создать зашифрованное сообщение
        'decr' => true,            // cryptcp: расшифровать сообщение
        // 'sign' => true,         // Дублируется (есть выше как 'Подписать сообщение'), но функциональность пересекается
        // 'verify' => true,       // Дублируется (есть выше как 'Проверить файл с подписью'), но функциональность пересекается
        'addsign' => true,         // cryptcp: добавить подпись в сообщение
        'delsign' => true,         // cryptcp: удалить подпись из сообщения
        'addattr' => true,         // cryptcp: добавить в подпись неподписанный атрибут
        'signf' => true,           // cryptcp: создать подписи файлов в 'исходный_файл.sgn'
        'vsignf' => true,          // cryptcp: проверить подписи файлов, созданные с помощью команды '-signf'
        'addsignf' => true,        // cryptcp: добавить подпись файла в 'исходный_файл.sgn'
        // 'hash' => true,         // Дублируется (есть выше как 'Получение хеша файла'), но функциональность пересекается
        'vhash' => true,           // cryptcp: проверить хэши файлов, созданные с помощью команды '-hash'
        'copycert' => true,        // cryptcp: скопировать сертификаты в заданное хранилище
        'cspcert' => true,         // cryptcp: скопировать сертификат из ключевого контейнера в хранилище
        'delcert' => true,         // cryptcp: удалить сертификат из хранилища
        'listdn' => true,          // cryptcp: вывести на экран политику имен КриптоПро УЦ
        'createuser' => true,      // cryptcp: зарегистрировать пользователя на КриптоПро УЦ
        'checkreg' => true,        // cryptcp: проверить состояние регистрации пользователя на КриптоПро УЦ
        'listtmpl' => true,        // cryptcp: вывести на экран шаблоны, доступные пользователю КриптоПро УЦ
        'createrqst' => true,      // cryptcp: создать запрос на сертификат и сохранить его в файле PKCS #10
        'instcert' => true,        // cryptcp: установить сертификат из файла PKCS #7 или файла сертификата
        'createcert' => true,      // cryptcp: создать запрос на сертификат, отправить его в ЦС
        'pendcert' => true,        // cryptcp: проверить, не выпущен ли сертификат
        'sn' => true,              // cryptcp: сохранить/показать серийный номер лицензии
        'nochain' => true,         // cryptcp: не включать цепочку сертификатов
        'thumbprint' => true,      // cryptcp: выбор сертификата по отпечатку

        'install' => true,         // certmgr: установить сертификат
        'delete' => true,          // certmgr: удалить сертификат
        'file' => true             // certmgr: установить сертификат из файла
    ];

    /**
     * Динамический вызов методов, соответствующих командам в $this->methods.
     * Позволяет удобно строить цепочки команд.
     *
     * @param string $name Имя вызываемого метода (команды).
     * @param array $arguments Аргументы, передаваемые команде.
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     * @throws BadMethodCallException Если метод не поддерживается.
     */
    public function __call(string $name, array $arguments): self
    {
        if (!array_key_exists($name, $this->methods)) {
            throw new BadMethodCallException("Метод '$name' не поддерживается");
        }

        $this->csp->addKey('-' . $name);

        // Если есть аргумент — добавь его тоже
        foreach ($arguments as $arg) {
            $this->csp->addKey($arg);
        }

        return $this;
    }

    /**
     * Регистрирует пользовательские методы, добавляя их к существующему списку.
     *
     * @param array $customMethods Массив новых методов для регистрации.
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     */
    public function registerMethods(array $customMethods): self
    {
        $this->methods += $customMethods;
        return $this;
    }

    /**
     * Обертка для добавления произвольного аргумента/ключа к команде.
     *
     * @param string $key Ключ или аргумент для добавления.
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     */
    public function addKey(string $key): self
    {
        $this->csp->addKey($key);

        return $this;
    }

    /**
     * Выводит список всех доступных контейнеров.
     *
     * @param bool $fullPath Если true, возвращает полный путь контейнера; иначе только имя.
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     */
    public function getContainers(bool $fullPath = true): self
    {
        $this->pattern = $fullPath ? (array)$this->patterns['containerFullPath'] : (array)$this->patterns['containerNameOnly'];

        $this->keyset()
            ->enum_cont()
            ->verifycontext()
            ->fqcn();

        return $this;
    }

    /**
     * Проверяет контейнер и подготавливает вывод результатов.
     *
     * @param string|null $container Имя/путь контейнера для проверки. Обязателен.
     * @param string|null $pass Пароль к контейнеру (опционально).
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     * @throws InvalidArgumentException Если контейнер не указан.
     */
    public function checkContainer(?string $container = null, ?string $pass = null): self
    {
        if (!$container) {
            throw new InvalidArgumentException("Не выбран контейнер.");
        }

        $this->keyset()
            ->check()
            ->cont($container)
            ->silent();

        if ($pass) {
            $this->csp->password($pass);
        }

        return $this;
    }

    /**
     * Сменить пароль контейнера.
     *
     * @param string|null $container Имя/путь контейнера. Обязателен.
     * @param string|null $newPass Новый пароль для контейнера. Обязателен.
     * @param string|null $currentPass Текущий пароль контейнера. Обязателен.
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     * @throws InvalidArgumentException Если не указан контейнер или пароли.
     */
    public function changeContainerPass(?string $container = null, ?string $newPass = null, ?string $currentPass = null): self
    {
        if (!$container || !$newPass) {
            throw new InvalidArgumentException("Не выбран контейнер или пароль.");
        }
    
        $this->passwd()
             ->change($newPass)
             ->cont($container);
        

        if (!empty($currentPass)) {
            $this->passwd($currentPass);
        }
            

        return $this;
    }

    /**
     * Подготавливает команду для копирования контейнера.
     *
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     */
    public function copyContainer(): self
    {
        $this->keycopy();

        return $this;
    }

    /**
     * Подготавливает команду для удаления контейнера.
     *
     * @param string|null $container Имя/путь контейнера для удаления. Обязателен.
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     * @throws InvalidArgumentException Если контейнер не указан.
     */
    public function deleteContainer(?string $container = null): self
    {
        if (!$container) {
            throw new InvalidArgumentException("Не выбран контейнер.");
        }

        $this->keyset()
            ->deletekeyset()
            ->container($container);

        return $this;
    }

    /**
     * Подготавливает команду для получения хэша файла.
     *
     * @param string $filePath Путь к файлу.
     * @param string $alg Алгоритм хэширования (по умолчанию 'GR3411_2012_512').
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     * @throws InvalidArgumentException Если файл не найден.
     */
    public function hashFile(string $filePath, string $alg = 'GR3411_2012_512'): self
    {
        if (!file_exists($filePath)) {
            throw new InvalidArgumentException("Файл не найден: $filePath");
        }

        $this->pattern = $this->patterns['hashFile']['patterns'];
        $this->expectedFields = $this->patterns['hashFile']['fields'];

        $this->mk()
            ->alg($alg)
            ->addKey($filePath);

        return $this;
    }

    /**
     * Подготавливает команду для проверки хэша файла.
     *
     * @param array $files Массив из 1 или 2 элементов: [исходный_файл, опционально_хэш_или_путь_к_нему].
     * @param string $alg Алгоритм хэширования (по умолчанию 'GR3411_2012_512').
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     * @throws InvalidArgumentException Если количество файлов некорректно, файл не найден, или формат хэша неверен.
     */
    public function verifyHash(array $files, string $alg = 'GR3411_2012_512'): self
    {
        $count = count($files);

        if ($count < 1 || $count > 2) {
            throw new InvalidArgumentException("Ожидался массив из 1 или 2 элементов: [исходный_файл, опционально_хэш_или_путь_к_нему].");
        }

        [$filePath, $hashOrPath] = [$files[0], $files[1] ?? null];

        if (!file_exists($filePath)) {
            throw new InvalidArgumentException("Файл не найден: $filePath");
        }

        $this->pattern = $this->patterns['verifyHash']['patterns'];
        $this->expectedFields = $this->patterns['verifyHash']['fields'];

        $this->addKey($filePath)
            ->alg($alg);

        if ($hashOrPath) {
            $hash = is_file($hashOrPath) ? trim(file_get_contents($hashOrPath)) : trim($hashOrPath);

            // Проверяем, что 'hashformat' в patterns - это строка, и используем её как паттерн
            if (!is_string($this->patterns['hashformat']) || !preg_match($this->patterns['hashformat'], $hash)) {
                throw new InvalidArgumentException("Неверный формат хэша или неверный путь.");
            }

            $this->addKey($hash);
        }

        return $this;
    }

    /**
     * Подготавливает команду для подписи документа.
     *
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     */
    public function signDocument(): self
    {
        $this->sfsign()
            ->sign();

        return $this;
    }

    /**
     * Подготавливает команду для проверки подписи на документе.
     *
     * @param array $files Массив файлов для проверки (1 для присоединенной, 2 для отсоединенной подписи).
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     * @throws InvalidArgumentException Если файл не найден или количество файлов некорректно.
     */
    public function verifySignature(array $files): self
    {
        foreach ($files as $filePath) {
            if (!file_exists($filePath)) {
                throw new InvalidArgumentException("Файл не найден: $filePath");
            }
        }

        $this->verify();

        // Паттерн для извлечения информации о подписанте
        // Убедитесь, что 'signatureOwner' - это строка-паттерн
        $this->pattern = (array)$this->patterns['signatureOwner'];

        // Проверка, сколько файлов передано
        if (count($files) === 1) {
            // Присоединенная подпись - 1 файл
            $this->attached()
                 ->nochain()
                 ->addKey(...$files); // Добавляем файлы как аргументы
        } elseif (count($files) === 2) {
            // Отсоединенная подпись - 2 файла
            $this->detached()
                 ->nochain()
                 ->addKey(implode(' ', $files)); // Добавляем файлы как аргументы
        } else {
            // Обработка ошибки, если файлов больше двух или меньше одного
            throw new InvalidArgumentException("Неверное количество файлов во входном массиве. Ожидается 1 или 2 файла.");
        }

        return $this;
    }

    /**
     * Подготавливает команду для шифрования документа.
     *
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     */
    public function encryptDocument(): self
    {
        $this->encr();

        return $this;
    }

    /**
     * Подготавливает команду для расшифровки файла.
     *
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     */
    public function decryptDocument(): self
    {
        $this->decr();

        return $this;
    }

    /**
     * Подготавливает команду для установки сертификата из файла или контейнера.
     *
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     */
    public function certificatInstall(): self
    {
        // Использование 'instcert' из методов cryptcp
        $this->install();

        return $this;
    }

    /**
     * Подготавливает команду для получения списка сертификатов.
     *
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     */
    public function getCertificates(): self
    {
        $this->pattern = $this->patterns['certificates']['patterns'];
        $this->expectedFields = $this->patterns['certificates']['fields'];
        $this->structureMatches = true; // Структурировать плоский вывод

        $this->list();

        return $this;
    }

    /**
     * Подготавливает команду для получения сертификата по отпечатку (или другим параметрам списка).
     *
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     */
    public function getCertificateByTp(): self
    {
        $this->pattern = $this->patterns['certificates']['patterns'];
        $this->expectedFields = $this->patterns['certificates']['fields'];
        $this->structureMatches = false; // Для одного сертификата не нужна структура

        $this->list();

        return $this;
    }

    /**
     * Подготавливает команду для удаления сертификата.
     *
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     */
    public function deleteCertificate(): self
    {
        // Использование 'delcert' из методов cryptcp
        $this->delete();

        return $this;
    }

    /**
     * Устанавливает кодировку для ConsoleRunner, если командная строка имеет проблемы с UTF-8 и кириллицей.
     *
     * @param string $code Кодировка (например, 'CP866').
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     */
    public function encoding(string $code): self
    {
        $this->csp->encoding($code);

        return $this;
    }

    /**
     * Устанавливает флаг для ConsoleRunner для возврата к исходной кодировке,
     * если вывод делается в ту же консоль.
     *
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     */
    public function decoding(): self
    {
        $this->csp->decoding();

        return $this;
    }

    /**
     * Устанавливает паттерны и ожидаемые поля для парсинга вывода из массива $patterns.
     *
     * @param string|null $patternName Имя паттерна из `$this->patterns`.
     * @param array|null $patternFields Массив с именами ключей для 'fields' и 'patterns' (например, ['fields', 'patterns']), если паттерн вложенный.
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     * @throws InvalidArgumentException Если паттерн не найден или структура `patternFields` неверна.
     */
    public function usePattern(?string $patternName = null, ?array $patternFields = null): self
    {
        if ($patternName === null) {
            $this->pattern = null;
            $this->expectedFields = null;
            $this->structureMatches = false;
            return $this;
        }

        if (!isset($this->patterns[$patternName])) {
            throw new InvalidArgumentException("Паттерн '{$patternName}' не найден.");
        }

        $patternData = $this->patterns[$patternName];

        if (is_array($patternData) && $patternFields !== null && count($patternFields) === 2) {
            [$fieldsKey, $patternsKey] = $patternFields;

            if (!isset($patternData[$patternsKey]) || !isset($patternData[$fieldsKey])) {
                throw new InvalidArgumentException("Массив с полями или паттернами для '{$patternName}' не найден по указанным ключам.");
            }

            $this->pattern = (array)$patternData[$patternsKey];
            $this->expectedFields = (array)$patternData[$fieldsKey];
        } else {
            // Если паттерн не является вложенным массивом с 'fields' и 'patterns'
            $this->pattern = is_array($patternData) ? $patternData : [$patternData];
            $this->expectedFields = null; // Сбрасываем, так как нет явных полей
        }

        return $this;
    }

    /**
     * Устанавливает флаг для структурирования выходных данных.
     *
     * @param bool $structure True, если данные должны быть структурированы, false иначе.
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     */
    public function useStructure(): self
    {
        $this->structureMatches = true;
        return $this;
    }

    /**
     * Добавляет пользовательские паттерны регулярных выражений к исходному массиву $patterns.
     *
     * @param array $patterns Массив паттернов для добавления.
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     */
    public function addPatterns(array $patterns): self
    {
        $this->patterns = array_merge($this->patterns, $patterns);
        return $this;
    }

    /**
     * Структурирует плоский массив совпадений в ассоциативный массив на основе заданных полей.
     *
     * @param array $matches Плоский массив совпадений.
     * @param array $fields Массив имен полей для структурирования.
     * @return array Массив структурированных данных.
     * @throws RuntimeException Если количество совпадений не соответствует структуре.
     */
    private function structureMatches(array $matches, array $fields): array
    {
        $chunkSize = count($fields);
        $matchesSize = count($matches);
        if ($chunkSize === 0) {
            return []; // Невозможно структурировать без полей
        }

        // Проверяем, что количество совпадений кратно размеру чанка
        if ($matchesSize % $chunkSize !== 0) {
             throw new RuntimeException("Несоответствие количества найденных совпадений ({$matchesSize}) и ожидаемых полей ({$chunkSize}) для структурирования.");
        }

        $structuredData = [];
        foreach (array_chunk($matches, $chunkSize) as $chunk) {
            $structuredData[] = array_combine($fields, $chunk);
        }

        return $structuredData;
    }

    /**
     * Выводит сгенерированную строку команды и завершает выполнение скрипта.
     * Полезно для отладки.
     *
     * @return null
     */
    public function printBuilderString(): ?string
    {
        exit($this->csp->getCommand());
    }

    /**
     * Запускает выполнение команды и обрабатывает результат.
     *
     * @return array Возвращает структурированный результат в случае успеха.
     * @throws RuntimeException В случае ошибки выполнения команды или парсинга.
     */
    public function run(): array
    {
        if ($this->csp->run()) {
            return $this->success();
        }

        $this->throwError();
    }


    /**
     * Обрабатывает успешное выполнение команды, парсит вывод и возвращает его.
     *
     * @return array Обработанный вывод.
     * @throws RuntimeException Если паттерны заданы, но данные не найдены, или неверное количество полей.
     */
    private function success(): array
    {
        if ($this->pattern === null) {
            return ['status' => 'успешно'];
        }

        $matches = $this->csp->getMatches($this->pattern);

        if (empty($matches)) {
            // Если паттерны заданы, но ничего не найдено
            throw new RuntimeException("Паттерны заданы, но данные не найдены в выводе.");
        }

        // Если ожидаемые поля заданы и количество совпадений соответствует количеству полей (один набор данных)
        if ($this->expectedFields !== null && count($matches) === count($this->expectedFields)) {
            return array_combine($this->expectedFields, $matches);
        }

        // Если включено структурирование и есть ожидаемые поля
        if ($this->structureMatches && $this->expectedFields !== null) {
            return $this->structureMatches($matches, $this->expectedFields);
        }

        // Если не удалось применить структурирование/комбинацию, возвращаем сырые совпадения
        return $matches;
    }

    /**
     * Обрабатывает ошибку выполнения команды, извлекая код ошибки.
     *
     * @return never
     * @throws RuntimeException Всегда выбрасывает исключение с кодом ошибки.
     */
    private function throwError(): never
    {
        // Поиск ошибки в формате [ErrorCode: 0x...]
        $pattern = '/\[ErrorCode:\s*(0x[0-9A-Fa-f]+)\]/';
        $matches = $this->csp->getMatches($pattern);

        if (empty($matches) || !isset($matches[0])) {
            throw new RuntimeException("Ошибка выполнения: Не удалось извлечь код ошибки.");
        }

        throw new RuntimeException("Ошибка выполнения, код: " . $matches[0]);
    }

}