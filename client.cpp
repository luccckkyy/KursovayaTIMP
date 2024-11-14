#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <openssl/sha.h>

using namespace std;

// Функция для чтения числовых векторов из файла
vector<vector<int>> readVectorsFromFile(const string& filename) {
    ifstream file(filename);
    if (!file.is_open()) {
        throw runtime_error("Failed to open input file");
    }

    int numVectors;
    file >> numVectors;

    vector<vector<int>> vectors;
    for (int i = 0; i < numVectors; ++i) {
        int vectorSize;
        file >> vectorSize;

        vector<int> vector;
        for (int j = 0; j < vectorSize; ++j) {
            int value;
            file >> value;
            vector.push_back(value);
        }
        vectors.push_back(vector);
    }

    return vectors;
}

// Функция для хэширования строки с использованием SHA-256
string sha256(const string& str, const string& salt) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, salt.c_str(), salt.size());
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);

    string hashed;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        char hex[3];
        sprintf(hex, "%02x", hash[i]);
        hashed += hex;
    }
    return hashed;
}

// Функция для отправки данных на сервер и получения результатов
void sendVectorsAndGetResults(int client, const vector<vector<int>>& vectors) {
    // Отправка количества векторов
    int numVectors = vectors.size();
    send(client, &numVectors, sizeof(numVectors), 0);

    for (const auto& vector : vectors) {
        // Отправка размера вектора
        int vectorSize = vector.size();
        send(client, &vectorSize, sizeof(vectorSize), 0);

        // Отправка значений вектора
        send(client, vector.data(), vectorSize * sizeof(int), 0);

        // Получение результатов
        int result;
        recv(client, &result, sizeof(result), 0);
        cout << "Result for vector: " << result << endl;
    }
}

// Функция для аутентификации на сервере
bool authenticateClient(int client, const string& login, const string& password) {
    // Отправка логина
    send(client, login.c_str(), login.size(), 0);

    // Получение соли
    char salt;
    recv(client, salt, 16, 0);
    salt = '\0';

    // Отправка хэша
    string hashed = sha256(password, salt);
    send(client, hashed.c_str(), hashed.size(), 0);

    // Получение результата аутентификации
    char response[4];
    recv(client, response, 3, 0);
    response[3] = '\0';

    return strcmp(response, "OK") == 0;
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        cout << "Usage: client <server_address> <port> <input_file> <output_file> [config_file]" << endl;
        return 1;
    }

    string serverAddress = argv[1];
    unsigned short port = atoi(argv[2]);
    string inputFilename = argv[3];
    string outputFilename = argv[4];
    string configFilename = argc > 5 ? argv[5] : "~/.config/vclient.conf";

    // Создание сокета
    int client = socket(AF_INET, SOCK_STREAM, 0);
    if (client == -1) {
        throw runtime_error("socket failed");
    }

    // Установка соединения с сервером
    sockaddr_in serverInfo;
    serverInfo.sin_family = AF_INET;
    serverInfo.sin_port = htons(port);
    inet_pton(AF_INET, serverAddress.c_str(), &serverInfo.sin_addr);

    if (connect(client, (sockaddr*)&serverInfo, sizeof(serverInfo)) == -1) {
        throw runtime_error("connect failed");
    }

    // Чтение логина и пароля из конфигурационного файла
    ifstream configFile(configFilename);
    if (!configFile.is_open()) {
        throw runtime_error("Failed to open config file");
    }

    string login, password;
    configFile >> login >> password;

    // Аутентификация на сервере
    if (!authenticateClient(client, login, password)) {
        throw runtime_error("Authentication failed");
    }

    // Чтение числовых векторов из файла
    vector<vector<int>> vectors = readVectorsFromFile(inputFilename);

    // Отправка данных на сервер и получение результатов
    sendVectorsAndGetResults(client, vectors);

    // Сохранение результатов в файл
    ofstream outputFile(outputFilename);
    if (!outputFile.is_open()) {
        throw runtime_error("Failed to open output file");
    }

    outputFile << vectors.size();
    for (const auto& vector : vectors) {
        outputFile << " " << vector.size();
        for (int value : vector) {
            outputFile << " " << value;
        }
    }

    // Закрытие сокета
    close(client);

    return 0;
}

