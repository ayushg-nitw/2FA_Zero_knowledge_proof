#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8080
#define MAX_LINE 1024
#define TOKEN_LENGTH 16

// Send token1 to server and receive halfway login status
int verify_token1(const char *username, const char *token1) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);
    
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    // Create request message
    char request[MAX_LINE];
    snprintf(request, sizeof(request), "ACTION: VERIFY_TOKEN1\nUsername: %s\nToken: %s\n",
           username, token1);
    
    // Send request
    send(sock, request, strlen(request), 0);
    
    // Get response
    char response[MAX_LINE];
    memset(response, 0, sizeof(response));
    recv(sock, response, sizeof(response), 0);
    printf("Server response: %s\n", response);
    
    close(sock);
    
    // Return 1 if halfway login successful
    return (strstr(response, "Halfway login done") != NULL);
}

// Send token2 to server and receive full login status
void verify_token2(const char *username, const char *token2) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);
    
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    // Create request message
    char request[MAX_LINE];
    snprintf(request, sizeof(request), "ACTION: VERIFY_TOKEN2\nUsername: %s\nToken: %s\n",
           username, token2);
    
    // Send request and wait for response
    send(sock, request, strlen(request), 0);
    
    // Get response
    char response[MAX_LINE];
    memset(response, 0, sizeof(response));
    recv(sock, response, sizeof(response), 0);
    printf("Server response: %s\n", response);
    
    close(sock);
}

int main() {
    char username[50], token1[TOKEN_LENGTH + 1], token2[TOKEN_LENGTH + 1];
    
    printf("=== Untrusted Device Login ===\n");
    printf("Enter username: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = 0; // Remove newline
    
    printf("Enter Token1 from trusted device: ");
    fgets(token1, sizeof(token1), stdin);
    token1[strcspn(token1, "\n")] = 0; // Remove newline
    
          if (verify_token1(username, token1)) {
            printf("\nHalfway login successful. Waiting for confirmation on trusted device...\n");

            // Clear input buffer
            int c;
            while ((c = getchar()) != '\n' && c != EOF);

            // Wait for user to confirm on trusted device and generate Token2
            printf("Enter Token2 from trusted device: ");
            fgets(token2, sizeof(token2), stdin);
            token2[strcspn(token2, "\n")] = 0; // Remove newline

            // Validate token2 length
            if (strlen(token2) != TOKEN_LENGTH) {
                printf("Warning: Token2 length is %lu, expected %d\n", 
                      strlen(token2), TOKEN_LENGTH);
            }

            // Verify Token2 to complete login
            verify_token2(username, token2);

            // Add a delay before closing to see the response
            printf("Press Enter to exit...\n");
            getchar();
        } else {
            printf("Login failed. Invalid Token1 or username.\n");
        }

    
    return 0;
}

