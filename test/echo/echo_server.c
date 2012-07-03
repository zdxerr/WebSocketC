
#include <process.h>

#include <winsock2.h>

#include <dbg.h>
#include <list.h>
#include <server.h>

#pragma comment(lib, "server.lib")

void control_thread(Server *server)
{
    char c;
    debug("Starting... (enter \"b\" to broadcast and \"q\" to quit)");
    do {
        c = getchar();
        if(c == 'b')
        {
            server_send(server, "Broadcasting.");
        }
    } while(c != 'q');
    server_stop(server);
}

int client_callback(Client *client, char *message, void *data)
{
    debug("Echo message: %s", message);
    client_send(client, message);
    return 0;
}

int main(int argc, char *argv[])
{
    Server *server = calloc(1, sizeof(Server));
    HANDLE thread = (HANDLE)_beginthread(control_thread, 0, server);

    server_start(server);
    server_set_callback(server, client_callback, NULL);

    WaitForSingleObject(thread, INFINITE);

    free(server);
    return 0;
}
