#pragma once

#include <stdbool.h>
#include <netinet/in.h>
#include <sys/socket.h>

bool get_dest_addr(int sockfd, struct sockaddr *accept_sa, struct sockaddr_storage *orig_dst);
bool redir_init();
void redir_close();

