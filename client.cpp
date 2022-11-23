#include "headers.h"
#include <openssl/sha.h>
using namespace std;

void *FromTracker(void *);
void *ToTracker(void *);

pthread_mutex_t lock_sha;
pthread_mutex_t lock_rec;
pthread_mutex_t lock_sen;
pthread_mutex_t lock_f;
pthread_mutex_t lock_shafile;

unordered_map<string, string> file_chunks;

struct trackerSocketDetails
{
    int arg1;
    string arg2;
    int cliport;
    string cliip;
};
struct socketDetails
{
    int arg1;
    int arg2;
};
struct clientDetails
{
    int socketId;
    int port;
    string ip;
};
struct downloadinfo
{
    int port;
    int port_of_me;
    int sockForserv;
    long long chunkno;
    string ip;
    string ip_of_me;
    string filename;
    string size;
    string gid;
    string despath;
    string srcpath;
    string shaval;
};
int check(int exp, const char *msg)
{
    if (exp == SOCKETERROR)
    {
        perror(msg);
        exit(1);
    }
    return exp;
}
long long convertToInt(string st)
{
    stringstream con(st);
    long long x = 0;
    con >> x;
    return x;
}
string getChunks(string len)
{
    long long int size = convertToInt(len);
    long long int no_of_chunks = size / CHUNK_SIZE;
    string bitmap = "";
    for (int i = 0; i < no_of_chunks; i++)
        bitmap += '0';
    if (size % CHUNK_SIZE != 0)
        bitmap += '0';
    return bitmap;
}
string getSHA(string filepath)
{
    string piecewiseSHA = "";

    // getting file size
    struct stat statbuf;
    stat(filepath.c_str(), &statbuf);
    intmax_t len = (intmax_t)statbuf.st_size;

    unsigned char sha_of_file[20];
    unsigned char *file_binary = new unsigned char[len];

    bzero(file_binary, sizeof(file_binary));
    bzero(sha_of_file, sizeof(sha_of_file));

    char encryptedText[40];
    int n = 0;

    pthread_mutex_lock(&lock_shafile);
    FILE *fp = NULL;
    fp = fopen(filepath.c_str(), "r+");
    if (fp == NULL)
    {
        perror("");
        cout << "ERROR" << endl;
        exit(-1);
    }
    n = fread(file_binary, 1, sizeof(file_binary), fp);
    fclose(fp);
    pthread_mutex_unlock(&lock_shafile);

    SHA1(file_binary, n, sha_of_file);
    for (int i = 0; i < 20; i++)
    {
        sprintf(encryptedText + 2 * i, "%02x", sha_of_file[i]);
    }

    piecewiseSHA = piecewiseSHA + encryptedText;
    free(file_binary);
    return piecewiseSHA;
}

void getPortandIp(char *argv[], vector<string> &trackerdetails, int &port, string &ip)
{
    FILE *fp;
    fp = fopen(argv[2], "r");

    if (fp)
    {
        char c;
        string p = "";
        for (char c = getc(fp); c != EOF; c = getc(fp))
        {
            if (c == ' ')
            {
                trackerdetails.push_back(p);
                p = "";
                continue;
            }
            p = p + c;
        }
        trackerdetails.push_back(p);
        p = "";
        fclose(fp);
    }
    else
    {
        cout << "Unable top open file" << endl;
        exit(-1);
    }
    string p = "";
    string agv = argv[1];
    for (int i = 0; i < agv.size(); i++)
    {
        if (argv[1][i] == ':')
        {
            ip = p;
            p = "";
            continue;
        }
        p = p + argv[1][i];
    }
    port = convertToInt(p);
}
string recvsha(string filepath, long long piecesize, off_t offset)
{
    unsigned char sha_of_file[20];
    unsigned char *file_binary = new unsigned char[piecesize];

    bzero(file_binary, sizeof(file_binary));
    bzero(sha_of_file, sizeof(sha_of_file));

    char encryptedText[40];

    pthread_mutex_lock(&lock_sha);
    int fp = 0;
    check(fp = open(filepath.c_str(), O_RDWR), "error in opening file");
    long long bytesReadFromFile = pread(fp, file_binary, CHUNK_SIZE, offset);
    close(fp);
    pthread_mutex_unlock(&lock_sha);

    SHA1(file_binary, bytesReadFromFile, sha_of_file);
    for (int i = 0; i < 20; i++)
    {
        sprintf(encryptedText + 2 * i, "%02x", sha_of_file[i]);
    }
    string piecewiseSHA = "";
    piecewiseSHA = piecewiseSHA + encryptedText;
    free(file_binary);
    return piecewiseSHA;
}
void *getConnection(void *args)
{

    struct downloadinfo *dinfo = (struct downloadinfo *)args;
    int port = dinfo->port;
    int port_of_me = dinfo->port_of_me;
    int sockForserv = dinfo->sockForserv;
    string ip = dinfo->ip;
    string ip_of_me = dinfo->ip_of_me;
    string filename = dinfo->filename;
    string size = dinfo->size;
    string gid = dinfo->gid;
    string despath = dinfo->despath;
    string srcpath = dinfo->srcpath;
    long long chunkno = dinfo->chunkno;
    string shaval = dinfo->shaval;

    int client_socd = 0;
    struct sockaddr_in address;
    int opt = 1;

    check((client_socd = socket(AF_INET, SOCK_STREAM, 0)), "socket of peer failed");
    check(setsockopt(client_socd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)), "setsockopt eeror");
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(ip.c_str());
    address.sin_port = htons(port);
    memset(&address.sin_zero, 0, sizeof(address.sin_zero));
    check((connect(client_socd, (struct sockaddr *)&address, sizeof(address))), "connection with peer failed");

    char data[4096] = {
        0,
    };

    recv(client_socd, data, 4096, 0);

    string filepath = despath + filename;

    data[4096] = {
        0,
    };
    string tosend = "requesting " + to_string(chunkno) + " " + gid + " " + filename + " " + srcpath;
    strcpy(data, tosend.c_str());
    send(client_socd, data, 4096, 0);
    data[4096] = {
        0,
    };

    recv(client_socd, data, 32, 0);
    long long pieceSize = convertToInt(data);

    char sha_of_piece[40];
    recv(client_socd, sha_of_piece, 40, 0);
    string sha = sha_of_piece;

    long long totBytesRead = 0;
    char *file_chunk = new char[pieceSize];
    bzero(file_chunk, sizeof(file_chunk));
    long long off = chunkno * CHUNK_SIZE;

    pthread_mutex_lock(&lock_rec);
    int fp = 0;
    check(fp = open(filepath.c_str(), O_RDWR), "error in opening file");
    while (totBytesRead < pieceSize)
    {
        bzero(file_chunk, sizeof(file_chunk));
        long bytesRead = recv(client_socd, file_chunk, pieceSize - totBytesRead, 0);
        totBytesRead += bytesRead;
        pwrite(fp, file_chunk, bytesRead, off);
        off = off + bytesRead;
    }
    close(fp);
    pthread_mutex_unlock(&lock_rec);

    off_t offset = chunkno * CHUNK_SIZE;
    string sha_of_received = recvsha(filepath, pieceSize, offset);

    if (sha.compare(sha_of_received) == 0)
    {
        // cout << "sha verified for chunk " << chunkno << endl;
        
        file_chunks[filepath][chunkno] = '1';
        string mychunkmap = file_chunks[filepath];
        data[4096] = {
            0,
        };
        string toserver = "chunk " + ip_of_me + " " + to_string(port_of_me) + " " + gid + " " + filename + " " + mychunkmap;
        strcpy(data, toserver.c_str());
        send(sockForserv, data, 4096, 0);
        bool flag =1;
        for(int i=0;i<file_chunks[filepath].size();i++)
        {
            if(file_chunks[filepath][i] == '0')
            {
                flag = 0;
                break;
            }
        }
        if(flag)
        {
            data[4096] = {
                0,
            };
            string shavalue_rec = getSHA(filepath);
            if (shaval == shavalue_rec)
            {
                string toserverc = "completed " + ip_of_me + " " + to_string(port_of_me) + " " + gid + " " + filename;
                strcpy(data, toserverc.c_str());
                send(sockForserv, data, 4096, 0);
                file_chunks.erase(filepath);
                cout << "--> SHA matched" << endl;
                cout << "--> Downloaded successfully" << endl;
            }
            else
                cout << "--> SHA do not matched" << endl;
        }

        sleep(5);
    }
    else
    {
        cout << "sha not matching for chunk " << chunkno << endl;
    }

    free(file_chunk);
    close(client_socd);
    pthread_exit(NULL);
}
string searchUser(unordered_map<string, pair<string, int>> portIpUsers, int port, string ip)
{
    string s;
    int p;
    for (auto m : portIpUsers)
    {

        s = m.second.first;
        p = m.second.second;

        if (port == p && ip == s)
        {
            return m.first;
        }
    }
    return "";
}
vector<pair<string, int>> givepeerinfo(vector<string> peerinfo, vector<string> &userinfo, string size_of_file, string filename)
{
    long long int len = convertToInt(size_of_file);
    long long int no_of_chunks = len / CHUNK_SIZE;
    if (len % CHUNK_SIZE != 0)
        no_of_chunks = no_of_chunks + 1;
    vector<vector<pair<string, int>>> chunkpeerinfo(no_of_chunks);
    vector<pair<string, int>> selectedpeers(no_of_chunks);
    unordered_map<string, pair<string, int>> uidportIp;
    int size = peerinfo.size() - 6;
    for (int i = 1; i <= size; i++)
    {
        string peer = peerinfo[i];
        string peerip = "";
        int peerport = 0;
        string uid = "";
        string temp = "";
        int j = 0;
        for (j = 0; j < peer.size(); j++)
        {
            if (peer[j] == '#')
            {
                uid = temp;
                temp = "";
                continue;
            }
            else if (peer[j] == ':')
            {
                peerip = temp;
                temp = "";
                continue;
            }
            else if (peer[j] == '$')
            {
                peerport = convertToInt(temp);
                temp = "";
                break;
            }
            temp = temp + peer[j];
        }

        uidportIp[uid] = make_pair(peerip, peerport);
        for (int k = j + 1, l = 0; k < peer.size(); k++, l++)
        {
            if (peer[k] == '1')
            {
                chunkpeerinfo[l].push_back(make_pair(peerip, peerport));
            }
        }
    }

    for (int i = 0; i < chunkpeerinfo.size(); i++)
    {
        int len_of_peerscount = chunkpeerinfo[i].size();
        int random = rand() % len_of_peerscount;
        selectedpeers[i] = chunkpeerinfo[i][random];
        pair<string, int> p = chunkpeerinfo[i][random];
        string user = searchUser(uidportIp, p.second, p.first);
        userinfo.push_back(user);
    }
    return selectedpeers;
}
void *FromTracker(void *arguments)
{
    struct clientDetails *args = (struct clientDetails *)arguments;
    int client_socd = args->socketId;
    int port_of_me = args->port;
    string ip_of_me = args->ip;
    while (1)
    {
        char data[4096] = {
            0,
        };
        int nRet = recv(client_socd, data, 4096, 0);
        if (nRet == 0)
        {
            cout << "--> connection with tracker is lost" << endl;
            close(client_socd);
            pthread_exit(NULL);
        }
        vector<string> received;
        istringstream sst(data);
        string inter;
        while (sst >> inter)
        {
            received.push_back(inter);
        }
        if (received[0] == "d")
        {
            vector<string> userinfo;

            pthread_t tid[60];
            string filename = received[received.size() - 2];
            string gid = received[received.size() - 3];
            string size = received[received.size() - 4];
            string shaval = received[received.size() - 5];
            string despath = received[received.size() - 1];
            string mychunkmap = getChunks(size);
            string filepath = despath + filename;
            file_chunks[filepath] = mychunkmap;

            vector<pair<string, int>> selectedpeers = givepeerinfo(received, userinfo, size, filename);
            struct downloadinfo dinfo[selectedpeers.size()];

            for (int i = 0; i < selectedpeers.size(); i++)
            {
                dinfo[i].port = selectedpeers[i].second;
                dinfo[i].port_of_me = port_of_me;
                dinfo[i].sockForserv = client_socd;
                dinfo[i].ip = selectedpeers[i].first;
                dinfo[i].ip_of_me = ip_of_me;
                dinfo[i].filename = filename;
                dinfo[i].size = size;
                dinfo[i].gid = gid;
                dinfo[i].despath = despath;
                dinfo[i].srcpath = userinfo[i];
                dinfo[i].chunkno = i;
                dinfo[i].shaval = shaval;
                // cout << selectedpeers[i].first << " " << selectedpeers[i].second << endl;
            }

            int fd = 0;
            mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
            if ((fd = creat(filepath.c_str(), mode)) < 0)
            {
                perror("File creation error.");
            }
            long long len = convertToInt(size);
            // ftruncate(fd, len);

            string toserverd = "downloading " + ip_of_me + " " + to_string(port_of_me) + " " + gid + " " + filename + " " + filepath;
            data[4096] = {
                0,
            };
            strcpy(data, toserverd.c_str());
            send(client_socd, data, 4096, 0);
            cout << "--> Downloading..." << endl;
            pthread_attr_t attr;
            pthread_attr_init(&attr);
            for (int i = 0; i < selectedpeers.size(); i++)
            {
                check(pthread_create(&tid[i], &attr, getConnection, (void *)&dinfo[i]), "Failed to create thread");
            }
            int t = 0;
            while (t < selectedpeers.size())
            {
                pthread_join(tid[t++], NULL);
                // cout << port_of_me << " " << t << endl;
            }
            // pthread_attr_destroy(&attr);
            // data[4096] = {
            //     0,
            // };
            // string shavalue_rec = getSHA(filepath);
            // if (shaval == shavalue_rec)
            // {
            //     string toserverc = "completed " + ip_of_me + " " + to_string(port_of_me) + " " + gid + " " + filename;
            //     strcpy(data, toserverc.c_str());
            //     send(client_socd, data, 4096, 0);
            //     file_chunks.erase(filepath);
            //     cout << "--> SHA matched" << endl;
            //     cout << "--> Downloaded successfully" << endl;
            // }
            // else
            //     cout << "--> SHA do not matched" << endl;
        }
        else
            cout << "--> " << data << endl;
    }
    pthread_exit(NULL);
}
string getFileName(string path)
{
    string dummy;
    stringstream ss(path);
    string intermediate;
    while (getline(ss, intermediate, '/'))
    {
        dummy = intermediate;
    }
    return dummy;
}
bool checkCount(vector<string> command, int count)
{
    if (command.size() == count)
        return true;
    else
        return false;
}
void *ToTracker(void *arguments)
{
    struct clientDetails *args = (struct clientDetails *)arguments;
    int client_socd = args->socketId;
    cout << "================================" << endl
         << "Enter Commands:" << endl
         << "--------------------------------" << endl
         << setw(15) << left << "create_user"
         << "<uid> <pwd>" << endl
         << setw(15) << left << "login"
         << "<uid> <pwd>" << endl
         << setw(15) << left << "create_group"
         << "<gid>" << endl
         << setw(15) << left << "join_group"
         << "<gid>" << endl
         << setw(15) << left << "leave_group"
         << "<gid>" << endl
         << setw(15) << left << "list_requests"
         << "<gid>" << endl
         << setw(15) << left << "accept_request"
         << "<gid> <uid>" << endl
         << setw(15) << left << "list_groups" << endl
         << setw(15) << left << "list_files"
         << "<gid>" << endl
         << setw(15) << left << "upload_file"
         << "<filepath> <gid>" << endl
         << setw(15) << left << "download_file"
         << "<gid> <filename> <des_path>" << endl
         << setw(15) << left << "show_downloads" << endl
         << setw(15) << left << "stop_share"
         << "<gid> <filename>" << endl
         << setw(15) << left << "logout" << endl

         << "================================" << endl;
    while (1)
    {
        char data[4096] = {
            0,
        };
        string inpFromUser;
        getline(cin, inpFromUser);
        if (inpFromUser.size() == 0)
            continue;
        vector<string> command;
        istringstream ss(inpFromUser);
        string intermediate;
        while (ss >> intermediate)
        {
            command.push_back(intermediate);
        }
        if (command[0] == "create_user" || command[0] == "accept_request" || command[0] == "login" ||
            command[0] == "stop_share" || command[0] == "create_group" || command[0] == "join_group" ||
            command[0] == "leave_group" || command[0] == "logout" || command[0] == "show_downloads" ||
            command[0] == "list_groups" || command[0] == "list_requests" || command[0] == "list_files" ||
            command[0] == "upload_file" || command[0] == "download_file")
        {
        }
        else
        {
            cout << "--> Invalid command" << endl;
            continue;
        }
        bool flag = 0;
        if ((command[0] == "create_user" || command[0] == "accept_request" || command[0] == "login" ||
             command[0] == "stop_share") &&
            !checkCount(command, 3))
            flag = 1;

        else if ((command[0] == "create_group" || command[0] == "join_group" || command[0] == "leave_group" ||
                  command[0] == "list_requests" || command[0] == "list_files") &&
                 !checkCount(command, 2))
            flag = 1;

        else if ((command[0] == "logout" || command[0] == "show_downloads" ||
                  command[0] == "list_groups") &&
                 !checkCount(command, 1))
            flag = 1;

        else if (command[0] == "upload_file")
        {
            if (!checkCount(command, 3))
            {
                cout << "--> Insufficient arguments" << endl;
                continue;
            }
            if (access(command[1].c_str(), F_OK) != 0)
            {
                cout << "--> file path is invalid" << endl;
                continue;
            }
            string shavalue = getSHA(command[1]);
            struct stat statbuf;
            check((stat(command[1].c_str(), &statbuf) == -1), "could not open file");
            intmax_t len = (intmax_t)statbuf.st_size;
            string filename = getFileName(command[1]);
            inpFromUser = command[0] + " " + filename + " " + command[2] + " " + shavalue + " " + to_string(len) + " " + command[1];
        }
        else if (command[0] == "download_file")
        {
            if (!checkCount(command, 4))
            {
                cout << "--> Insufficient arguments" << endl;
                continue;
            }
            // Check for path existence
            struct stat stats;
            stat(command[3].c_str(), &stats);
            if (!S_ISDIR(stats.st_mode))
            {
                cout << "--> Invalid destination path" << endl;
                continue;
            }
            int s = command[3].size() - 1;
            if (command[3][s] != '/')
                command[3] = command[3] + '/';
            inpFromUser = command[0] + " " + command[1] + " " + command[2] + " " + command[3];
        }
        if (flag)
        {
            cout << "--> Insufficient arguments" << endl;
            continue;
        }
        if (command[0].compare("create_user") != 0)
            inpFromUser = inpFromUser + " " + args->ip + " " + to_string(args->port);
        // cout<<inpFromUser<<endl;
        strcpy(data, inpFromUser.c_str());
        send(client_socd, data, 4096, 0);
    }
    pthread_exit(NULL);
}
void *establishConnectionTracker(void *arguments)
{

    struct trackerSocketDetails *args = (struct trackerSocketDetails *)arguments;
    int port = args->arg1;
    string ip = args->arg2;
    int client_socd;
    struct sockaddr_in address;
    int opt = 1;
    check((client_socd = socket(AF_INET, SOCK_STREAM, 0)), "socket failed");

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(ip.c_str());
    address.sin_port = htons(port);
    memset(&address.sin_zero, 0, sizeof(address.sin_zero));
    check((connect(client_socd, (struct sockaddr *)&address, sizeof(address))), "connection with tracker failed");
    char buf[4096] = {
        0,
    };

    pthread_t fromTracker, toTracker;
    struct clientDetails cd;
    cd.socketId = client_socd;
    cd.ip = args->cliip;
    cd.port = args->cliport;

    pthread_create(&fromTracker, NULL, FromTracker, (void *)&cd);
    pthread_create(&toTracker, NULL, ToTracker, (void *)&cd);

    pthread_join(fromTracker, NULL);
    pthread_join(toTracker, NULL);

    pthread_exit(NULL);
}

void *acceptConnection(void *arguments)
{
    struct socketDetails *args = (struct socketDetails *)arguments;
    int port = args->arg1;
    int clientSocD = args->arg2;
    char data[4096] = {
        0,
    };

    send(clientSocD, "ok I will send you", 4096, 0);
    int nRet = recv(clientSocD, data, 4096, 0);
    if (nRet == 0)
    {
        cout << "--> connection with client is lost" << endl;
        close(clientSocD);
        pthread_exit(NULL);
    }
    vector<string> received;
    istringstream sst(data);
    string inter;
    while (sst >> inter)
    {
        received.push_back(inter);
    }
    if (received[0] == "requesting")
    {
        long long chunkno = convertToInt(received[1]);
        string gid = received[2];
        string filename = received[3];
        string filepath = received[4];

        // cout<<"downloading from"<<chunkno <<" "<<clientSocD<<endl;

        pthread_mutex_lock(&lock_f);
        FILE *fp = fopen(filepath.c_str(), "r+");
        if (fp == NULL)
        {
            perror("file does not exist");
            pthread_exit(NULL);
        }
        long piece_size = 0;
        fseek(fp, chunkno * CHUNK_SIZE, SEEK_SET);
        long piece_begin = ftell(fp);
        fseek(fp, 0, SEEK_END);
        long file_end = ftell(fp);
        fclose(fp);
        pthread_mutex_unlock(&lock_f);

        if (file_end > piece_begin + CHUNK_SIZE - 1)
        {
            piece_size = CHUNK_SIZE;
        }
        else
        {
            piece_size = file_end - piece_begin;
        }
        send(clientSocD, to_string(piece_size).c_str(), 32, 0);

        off_t offset = chunkno * CHUNK_SIZE;
        string sha_of_piece = recvsha(filepath, piece_size, offset);
        char shachar[40] = {
            0,
        };
        strcpy(shachar, sha_of_piece.c_str());
        send(clientSocD, shachar, 40, 0);

        char *file_chunk = new char[piece_size];
        bzero(file_chunk, sizeof(file_chunk));

        long long bytesReadFromFile = 0;
        pthread_mutex_lock(&lock_sen);
        int fd = 0;
        check(fd = open(filepath.c_str(), O_RDWR), "error in opening file");
        bytesReadFromFile = pread(fd, file_chunk, CHUNK_SIZE, offset);
        close(fd);
        pthread_mutex_unlock(&lock_sen);

        sleep(2);
        send(clientSocD, file_chunk, bytesReadFromFile, 0);
        data[4096] = {
            0,
        };
        close(clientSocD);
        free(file_chunk);
        // cout<<"exiting from"<<chunkno <<" "<<clientSocD<<endl;
        pthread_exit(NULL);
    }
    pthread_exit(NULL);
}
void startListening(int port, string ip1, int &server_socd, struct sockaddr_in &address)
{

    int opt = 1;
    check((server_socd = socket(AF_INET, SOCK_STREAM, 0)), "socket failed");

    check(setsockopt(server_socd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)), "setsockopt eeror");
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(ip1.c_str());
    address.sin_port = htons(port);

    check(bind(server_socd, (struct sockaddr *)&address, sizeof(address)), "bind failed");
    check(listen(server_socd, 3), "listen error");

    cout << "--> waiting for connection at " << port << endl;
}
void covertAsServer(int cliport, string ip)
{

    pthread_t tid[50];
    int server_socd;
    struct sockaddr_in address;
    startListening(cliport, ip, server_socd, address);
    int i = 0;
    struct socketDetails args[50];

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    while (1)
    {
        int clientSocD = 0;
        socklen_t len = sizeof(struct sockaddr);

        check((clientSocD = accept(server_socd, (struct sockaddr *)&address, &len)), "accept error");
        args[i].arg1 = cliport;
        args[i].arg2 = clientSocD;

        check(pthread_create(&tid[i], &attr, acceptConnection, (void *)&args[i]), "Failed to create thread");
        i++;

        if (i >= 50)
        {
            i = 0;
            while (i < 50)
            {
                pthread_join(tid[i++], NULL);
            }
            i = 0;
        }
    }
    // pthread_attr_destroy(&attr);
}
int main(int argc, char *argv[])
{

    if (pthread_mutex_init(&lock_sha, NULL) != 0)
    {
        printf("\n mutex init failed\n");
        return 1;
    }
    if (pthread_mutex_init(&lock_rec, NULL) != 0)
    {
        printf("\n mutex init failed\n");
        return 1;
    }
    if (pthread_mutex_init(&lock_sen, NULL) != 0)
    {
        printf("\n mutex init failed\n");
        return 1;
    }
    if (pthread_mutex_init(&lock_shafile, NULL) != 0)
    {
        printf("\n mutex init failed\n");
        return 1;
    }
    if (argc < 3)
    {
        cout << "Insufficiet command line arguments" << endl;
        exit(-1);
    }
    vector<string> tracker_details;
    int port;
    string ip;
    getPortandIp(argv, tracker_details, port, ip);
    int tracker_port = convertToInt(tracker_details[1]);
    pthread_t peerToTracker;
    struct trackerSocketDetails args;
    args.arg1 = tracker_port;
    args.arg2 = tracker_details[0];
    args.cliip = ip;
    args.cliport = port;
    check(pthread_create(&peerToTracker, NULL, establishConnectionTracker, (void *)&args), "Failed to create thread");
    covertAsServer(port, ip);
    return 0;
}
