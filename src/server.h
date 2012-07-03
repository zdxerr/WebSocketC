
/* A simple websocket server implementing the rfc6455 (http://tools.ietf.org/html/rfc6455) */

#ifndef _server_h
#define _server_h

#define PORT 80
#define TIMEOUT 1000
#define BUFFER_SIZE 2048
#define CLIENTS_SIZE 20

/* Websocket Handshake Template */
static const char HEADER_GET[] = "GET %s HTTP/1.1";
static const char HEADER_UPGRADE[] = "Upgrade: websocket";
static const char HEADER_CONNECTION[] = "Connection: Upgrade";
static const char HEADER_HOST[] = "Host: ";
static const char HEADER_KEY[] = "Sec-WebSocket-Key: ";
static const char HEADER_VERSION[] = "Sec-WebSocket-Version: ";
static const char HEADER_EXTENSION[] = "Sec-WebSocket-Extensions: ";
static const char HEADER_PROTOCOL[] = "Sec-WebSocket-Protocol: ";

static const char HEADER_SEND[] = "HTTP/1.1 101 Switching Protocols\r\n"\
                                  "Upgrade: websocket\r\n"\
                                  "Connection: Upgrade\n\r"\
                                  "Sec-WebSocket-Accept: %s\r\n"\
                                  "Sec-WebSocket-Protocol: %s\r\n\r\n";

/* WebSocket Universally Unique IDentifier */
static const char WS_UUID[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
#define WS_UUID_LENGTH 38

enum OPCODE {
    CONTINUATION = 0x0,
    TEXT = 0x1,
    BINARY = 0x2,
    CLOSE = 0x8,
    PING = 0x9,
    PONG = 0x10
};

#define HANDSHAKE_KEY_LENGTH 128
#define HANDSHAKE_RESOURCE_LENGTH 20
#define HANDSHAKE_HOST_LENGTH 50
#define HANDSHAKE_EXTENSION_LENGTH 200
#define HANDSHAKE_PROTOCOL_LENGTH 100

typedef struct Handshake {
    char resource[HANDSHAKE_RESOURCE_LENGTH];
    int upgrade;
    int connection;
    char host[HANDSHAKE_HOST_LENGTH];
    char received_key[HANDSHAKE_KEY_LENGTH];
    char send_key[HANDSHAKE_KEY_LENGTH];
    int version;
    char extension[HANDSHAKE_EXTENSION_LENGTH];
    char protocol[HANDSHAKE_PROTOCOL_LENGTH];
} Handshake;

typedef struct Client Client;

typedef int (*ClientCallback)(Client *client, char *message, void *data);

struct Client {
    int stop;
    HANDLE thread; /**< Thread handle for a single client */
    SOCKET socket; /**< Socket which is connected to the client */

    ClientCallback callback;
    void *callback_data;
};

typedef struct Server Server;

struct Server {
    int stop;
    HANDLE thread; /**< Main thread handle, this thread accepts connections and creates the client threads */
    SOCKET socket; /**< Listening socket for incomming connections */
    List *clients; /**< List of connected clients */

    ClientCallback callback;
    void *callback_data;
};

typedef struct Frame {
    int fin;
    int opcode;
    int masked;
    unsigned long long length;
    unsigned int keys[4];
    char *data;
} Frame;

void server_start(Server *server);
void server_stop(Server *server);

void client_set_callback(Client *client, ClientCallback callback, void *data);

int server_send(Server *self, char *message);
int client_send(Client *client, char *message);

#endif
