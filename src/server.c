
/* A simple websocket server implementing the rfc6455 (http://tools.ietf.org/html/rfc6455) */

#include <stdlib.h>
#include <string.h>

#include <process.h>

#include <winsock2.h>
#include <windows.h>

#include "dbg.h"
#include "sha1.h"
#include "base64.h"
#include "list.h"
#include "server.h"

#pragma comment(lib, "Ws2_32.lib")

static void server_thread(Server *self);
static void client_thread(Client *client);

static int handshake(char *out, char *in);

static Frame *frame_unpack(char *raw, size_t *frame_length);
static char *frame_pack(char *data, size_t data_length, size_t *frame_length);

/* Start the server thread */
void server_start(Server *server)
{
    server->thread = (HANDLE)_beginthread(server_thread, 0, server);
}

/* Stop the server thread and all client threads and perform cleanup actions. */
void server_stop(Server *server)
{
    server->stop = TRUE;
    while(server->clients)
    {
        Client *client;
        server->clients = list_pop(server->clients, &client);
        client->stop = TRUE;
        closesocket(client->socket);
        WaitForSingleObject(client->thread, INFINITE);
        free(client);
    }

    closesocket(server->socket);
    WaitForSingleObject(server->thread, INFINITE);
}

/* Accept tcp connections and create client threads for them. */
static void server_thread(Server *self)
{
    WSADATA wsa_data = {0};
    struct sockaddr_in socket_config;
    unsigned int recv_timeout_ms = TIMEOUT;

    /* initialize winsock */
    check(WSAStartup(MAKEWORD(2, 2), &wsa_data) == 0, "WSAStartup failed: %d", WSAGetLastError());

    /* Confirm that the WinSock DLL supports 2.2.*/
    check(LOBYTE(wsa_data.wVersion) == 2 && HIBYTE(wsa_data.wVersion) == 2, "Unsupported winsock version.");

    /* create udp socket */
    self->socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    check(self->socket != INVALID_SOCKET, "Failed to create socket: %d", WSAGetLastError());

    /* Receive data on the specified port from *ANY* network interface */
    socket_config.sin_family = AF_INET;
    socket_config.sin_addr.s_addr = INADDR_ANY;
    socket_config.sin_port = htons(PORT);

    error = bind(self->socket, (struct sockaddr *)&socket_config, sizeof(socket_config));
    check(error == 0, "Failed to bind socket: %d", WSAGetLastError());

    /* Sets the timeout, in milliseconds, for blocking receive calls. */
    error = setsockopt(self->socket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&recv_timeout_ms, sizeof(unsigned int));
    check(error == 0, "Failed to set socket receive timeout: %d", WSAGetLastError());

    while(!self->stop)
    {
        Client *client = calloc(1, sizeof(Client));
        /* start listening */
        error = listen(self->socket, SOMAXCONN);
        check(error == 0, "Listen failed with error: %d", WSAGetLastError());

        /* wait for client */
        client->socket = accept(self->socket, NULL, NULL);
        if(client->socket == INVALID_SOCKET)
        {
            error = WSAGetLastError();
            switch(error)
            {
                case WSAECONNRESET:
                case WSAEINTR:
                    continue;
                default:
                    log_err("accept failed: %d", error);
                    goto error;
            }
        }

        client_set_callback(client, self->callback, self->callback_data);

        /* create new thread for this client */
        client->thread = (HANDLE)_beginthread(client_thread, 0, client);

        self->clients = list_push(self->clients, client);
    }
error:
    closesocket(self->socket);
    /* call WSACleanup when done using the Winsock dll */
    WSACleanup();
    _endthread();
}

/* Calling the callback function when receiving a frame */
static void client_thread(Client *client)
{
    int error = 0;
    char buffer[BUFFER_SIZE];
    debug("thread start 0x%X", client);
    /* receive handshake */
    error = recv(client->socket, buffer, BUFFER_SIZE, 0);
    if(error == SOCKET_ERROR)
    {
        error = WSAGetLastError();
        if(error != WSAETIMEDOUT)
        {
            log_err("An unexpected error occured: %d", error); /* timeouts are expected */
        }
        log_warn("timeout");
        return;
    }

    error = handshake(buffer, buffer);
    check(error == 0, "Handshake creation failed.");

    /*send handshake */
    error = send(client->socket, buffer, strlen(buffer), 0);
    if(error == SOCKET_ERROR)
    {
        debug("send failed with error: %d\n", WSAGetLastError());
    }

    while(!client->stop)
    {
        Frame *frame = NULL;
        size_t frame_length = 0;
        unsigned int offset = 0;

        error = recv(client->socket, buffer, BUFFER_SIZE, 0);
        if(error == SOCKET_ERROR)
        {
            error = WSAGetLastError();
            switch(error)
            {
                case WSAETIMEDOUT:
                case WSAENOTSOCK:
                case WSAEINTR:
                case WSAECONNABORTED:
                    continue;
                case WSAECONNRESET:
                    /* connection is closed */
                    client->stop = TRUE;
                    break;
                default:
                    log_err("An unexpected error occured: %d", error); /* timeouts are expected */
                    goto error;
            }
        }

        while(!client->stop && offset < error )
        {
            frame = frame_unpack(&buffer[offset], &frame_length);
            switch(frame->opcode)
            {
                case CLOSE:
                    client->stop = TRUE;
                case TEXT:
                    offset += frame_length;
                    if(client->callback)
                        client->callback(client, frame->data, client->callback_data);
                default:
                    break;
            }
        }
    }
error:
    closesocket(client->socket);
    _endthread();
}

/* Create an accept-key from the received key */
static void make_accept(char *received_key, char *accept)
{
    #define CONCAT_LENGTH HANDSHAKE_KEY_LENGTH + WS_UUID_LENGTH
    char concat_key[CONCAT_LENGTH];
    char sha1_key[SHA1_DIGEST_SIZE];
    char base64_key[HANDSHAKE_KEY_LENGTH]; /* base64 encoding length is approximately 4 * (n / 3 + 1) */

    /* first concatenate the received key with the uuid */
    strncpy(concat_key, received_key, HANDSHAKE_KEY_LENGTH);
    strncat(concat_key, WS_UUID, WS_UUID_LENGTH);

    /* calculate the sha-1 of the concatenated keys */
    sha1(sha1_key, (unsigned char *)concat_key, strlen(concat_key));

    /* calculate the base64 representation */
    base64_encode(base64_key, sha1_key, SHA1_DIGEST_SIZE);

    strncpy(accept, base64_key, HANDSHAKE_KEY_LENGTH);
}

/* Create the outgoing handshake from an incomming handshake request. */
static int handshake(char *out, char *in)
{
    Handshake hs;
    char *token = NULL;

    #define CHECK_HEADER(l, field) strncmp(token, HEADER_##field, strlen(HEADER_##field)) == 0

    check(sscanf(in, HEADER_GET, hs.resource) == 1, "Invalid HTTP GET request."); /* not a get request, try again */
    token = strtok(in, "\r\n");
    while(token)
    {
        if(CHECK_HEADER(token, UPGRADE))
            hs.upgrade = TRUE;
        else if(CHECK_HEADER(token, CONNECTION))
            hs.connection = TRUE;
        else if(CHECK_HEADER(token, HOST))
            strncpy(hs.host, &token[strlen(HEADER_HOST)], HANDSHAKE_HOST_LENGTH);
        else if(CHECK_HEADER(token, KEY))
            strncpy(hs.received_key, &token[strlen(HEADER_KEY)], HANDSHAKE_KEY_LENGTH);
        else if(CHECK_HEADER(token, VERSION))
            hs.version = atoi(&token[strlen(HEADER_VERSION)]);
        else if(CHECK_HEADER(token, EXTENSION))
            strncpy(hs.extension, &token[strlen(HEADER_EXTENSION)], HANDSHAKE_EXTENSION_LENGTH);
        else if(CHECK_HEADER(token, PROTOCOL))
            strncpy(hs.protocol, &token[strlen(HEADER_PROTOCOL)], HANDSHAKE_PROTOCOL_LENGTH);
        token = strtok(NULL, "\r\n");
    }

    check(hs.upgrade && hs.connection && hs.host && hs.received_key && hs.version, "Invalid websocket handshake.");

    make_accept(hs.received_key, hs.send_key);

    debug("Handshake request from %s:\n\tReceived key: \t%s\n\tSend key: \t%s", hs.host, hs.received_key, hs.send_key);

    sprintf(out, HEADER_SEND, hs.send_key, hs.protocol);
    return 0;
error:
    return -1;
}

static Frame *frame_unpack(char *raw, size_t *frame_length)
{
    Frame *frame = calloc(1, sizeof(Frame));
    char *temp;
    int offset;
    check_mem(frame);

    /* Grab the header.
     * This single byte holds some flags nobody cares about, and an opcode which nobody cares about. */
    /* Get the fin, which states if this is the final fragment */
    frame->fin = *raw & 0x80;
    /* Check if reserved flag is set. Pork chop sandwiches! */
    check(!(*raw & 0x70), "Reserved flag in frame (0x%X).", *raw & 0x70);

    /* Get the opcode, and translate it to a local enum which we actually care about. */
    frame->opcode = *raw & 0xF;
    check(frame->opcode & TEXT || frame->opcode & CLOSE, "Received frame with unsupported opcode (0x%X)!",
          frame->opcode);

    /* Get the payload length and determine whether we need to look for an extra length. */
    temp = &raw[1];
    frame->masked = (int)*temp & 0x80;
    frame->length = (unsigned long long)*temp & 0x7f;

    /* The offset we're gonna be using to walk through the frame. We use this because the offset is variable
     * depending on the length and mask. */
    offset = 2;
    /* Extra length fields. */
    if(frame->length == 0x7E)
    {
        temp = &raw[2];
        frame->length = (unsigned long long)*temp & 0xFFFF;
        offset += 2;
    }
    else if(frame->length == 0x7F)
    {
        /* Protocol bug: The top bit of this long long *must* be cleared; that is, it is expected to be
         * interpreted as signed. That's fucking stupid, if you don't mind me saying so, and so we're
         * interpreting it as unsigned anyway. If you wanna send exabytes of data down the wire, then go ahead! */
        frame->length = (unsigned long long)*temp & 0xFFFFFFFFFFFFFFFF;
        offset += 8;
    }

    if(frame->masked)
    {
        temp = &raw[offset];
        frame->keys[0] = temp[0] & 0xFF;
        frame->keys[1] = temp[1] & 0xFF;
        frame->keys[2] = temp[2] & 0xFF;
        frame->keys[3] = temp[3] & 0xFF;
        offset += 4;
    }

    frame->data = calloc(frame->length + 1, sizeof(char));
    memcpy(frame->data, &raw[offset], frame->length);

    if(frame->masked)
    {
        /* Mask or unmask a buffer of bytes with a masking key.
         * The key must be exactly four bytes long. */
        unsigned long long i;
        for(i=0;i<frame->length;i++)
        {
            frame->data[i] ^= frame->keys[i % 4];
        }
    }
    /* null-terminate the payload... */
    frame->data[frame->length] = '\0';

    *frame_length = 2 + (frame->length > 0x7E ? 2 : 0) + (frame->masked ? 4 : 0) + frame->length;
    debug("Parsed valid frame.\n\tOPCODE: 0x%02X MASKED: %.6s LENGTH: %llu KEYS: 0x%02X%02X%02X%02X\n\t%s",
          frame->opcode, frame->masked ? "TRUE" : "FALSE", frame->length, frame->keys[0], frame->keys[1],
          frame->keys[2], frame->keys[3], frame->data);
error:
    return frame;
}

/* This function always creates unmasked frames, and attempts to use the smallest possible lengths. */
static char *frame_pack(char *data, size_t data_length, size_t *frame_length)
{
    unsigned int offset;
    char *raw;

    *frame_length = 2 + (data_length > 0x7E ? 2 : 0) + data_length;
    raw = calloc(*frame_length, sizeof(char));
    check_mem(raw);

    /* pack header */
    raw[0] = 0x80 | TEXT;

    /* set length */
    check(data_length <= 0xFFFF, "Data packets larger than %u are not supported.", 0xFFFF);
    if(data_length > 0x7E)
    {
        raw[1] = 0x7E;
        memcpy(&raw[2], &data_length, 2);
        offset = 4;
    }
    else
    {
        raw[1] = data_length;
        offset = 2;
    }

    /*copy data */
    memcpy(&raw[offset], data, data_length);
    debug("Packed frame.\n\tOPCODE: 0x%02X LENGTH: %u\n\t%s", TEXT, *frame_length, data);
    return raw;
error:
    free(raw);
    return NULL;
}

void server_set_callback(Server *server, ClientCallback callback, void *data)
{
    server->callback = callback;
    server->callback_data = data;
}

void client_set_callback(Client *client, ClientCallback callback, void *data)
{
    client->callback = callback;
    client->callback_data = data;
}

int server_send(Server *server, char *message)
{
    List *node;
    list_foreach(server->clients, node)
    {
        Client *client = (Client *)list_value(node);
        client_send(client, message);
    }
    return 0;
}

int client_send(Client *client, char *message)
{
    size_t frame_length;
    char *send_buffer = frame_pack(message, strlen(message), &frame_length);
    check(send_buffer, "Frame packing failed.");;

    if(send(client->socket, send_buffer, frame_length, 0) == SOCKET_ERROR)
    {
        error = WSAGetLastError();
        switch(error)
        {
            case WSAECONNABORTED:
                client->stop = TRUE;
            default:
                log_err("send failed with error: %d\n", error);
        }
    }
error:
    free(send_buffer);
    return 0;
}
