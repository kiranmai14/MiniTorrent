#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <cstdio>
#include <vector>
#include <sstream>
#include <arpa/inet.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <functional>
#include <unordered_map>
#include <iomanip>
#include <cstring>
#include <queue>
#include <semaphore.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <unordered_set>
#include <algorithm>
#include<cstdlib>


#define REGISTERED "Registered Successfully"
#define LOGGEDIN "LoggedIn Successfully"
#define LOGGEDIN "LoggedIn Successfully"
#define CHUNK_SIZE 524288

#define SOCKETERROR (-1)