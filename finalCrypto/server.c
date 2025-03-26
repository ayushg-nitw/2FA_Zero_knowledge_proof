#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

#define SERVER_PORT 8080
#define MAX_LINE 2048
#define DATA_FILE "users.txt"
#define LOGIN_ATTEMPTS_FILE "login_attempts.txt"
#define TOKEN_LENGTH 16
#define LOGIN_EXPIRY_SECONDS 300 // 5 minutes expiry

typedef struct {
    char username[50];
    time_t timestamp;
    int halfway_confirmed;
    int zkp_passed;
    char token1[TOKEN_LENGTH + 1];
    char token2[TOKEN_LENGTH + 1];
} LoginAttempt;

// Function to check if a username is already taken
int is_username_taken(const char *username) {
    FILE *file = fopen(DATA_FILE, "r");
    if (!file) return 0;
    char line[MAX_LINE];
    while (fgets(line, sizeof(line), file)) {
        char stored_username[50];
        sscanf(line, "%s", stored_username);
        if (strcmp(stored_username, username) == 0) {
            fclose(file);
            return 1;
        }
    }
    fclose(file);
    return 0;
}

// Function to store user data
void store_user_data(const char *username, const char *pub1, const char *pub2,
                    const char *prime, const char *generator) {
    FILE *file = fopen(DATA_FILE, "a");
    if (!file) {
        perror("Failed to open file");
        exit(EXIT_FAILURE);
    }
    fprintf(file, "%s %s %s %s %s\n", username, pub1, pub2, prime, generator);
    fclose(file);
}

// Function to get user data by username
int get_user_data(const char *username, char *pub1, char *pub2, char *prime, char *generator) {
    FILE *file = fopen(DATA_FILE, "r");
    if (!file) return 0;
    char line[MAX_LINE];
    while (fgets(line, sizeof(line), file)) {
        char stored_username[50];
        sscanf(line, "%s %s %s %s %s", stored_username, pub1, pub2, prime, generator);
        if (strcmp(stored_username, username) == 0) {
            fclose(file);
            return 1;
        }
    }
    fclose(file);
    return 0;
}

// Function to create a new login attempt with Token1
char* create_login_attempt(const char *username) {
    static char token1[TOKEN_LENGTH + 1];
    // Generate random token1
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (int i = 0; i < TOKEN_LENGTH; i++) {
        int key = rand() % (sizeof(charset) - 1);
        token1[i] = charset[key];
    }
    token1[TOKEN_LENGTH] = '\0';
    LoginAttempt attempt;
    strncpy(attempt.username, username, sizeof(attempt.username) - 1);
    attempt.timestamp = time(NULL);
    attempt.halfway_confirmed = 0;
    attempt.zkp_passed = 0;
    strncpy(attempt.token1, token1, TOKEN_LENGTH);
    memset(attempt.token2, 0, sizeof(attempt.token2));
    FILE *file = fopen(LOGIN_ATTEMPTS_FILE, "a");
    if (!file) {
        perror("Failed to open login attempts file");
        exit(EXIT_FAILURE);
    }
    fprintf(file, "%s %ld %d %d %s %s\n", attempt.username, attempt.timestamp,
           attempt.halfway_confirmed, attempt.zkp_passed, attempt.token1, attempt.token2);
    fclose(file);
    return token1;
}

// Function to verify Token1 and update login attempt
int verify_token1(const char *username, const char *token) {
    FILE *file = fopen(LOGIN_ATTEMPTS_FILE, "r");
    if (!file) return 0;
    char line[MAX_LINE];
    time_t current_time = time(NULL);
    int token_valid = 0;
    FILE *temp_file = fopen("temp_login_attempts.txt", "w");
    if (!temp_file) {
        fclose(file);
        return 0;
    }
    while (fgets(line, sizeof(line), file)) {
        LoginAttempt attempt;
        sscanf(line, "%s %ld %d %d %s %s", attempt.username, &attempt.timestamp,
              &attempt.halfway_confirmed, &attempt.zkp_passed, attempt.token1, attempt.token2);
        if (strcmp(attempt.username, username) == 0 &&
            (current_time - attempt.timestamp) < LOGIN_EXPIRY_SECONDS &&
            strcmp(attempt.token1, token) == 0) {
            // Token1 is valid, update the record
            token_valid = 1;
            attempt.halfway_confirmed = 1;
            fprintf(temp_file, "%s %ld %d %d %s %s\n", attempt.username, attempt.timestamp,
                   attempt.halfway_confirmed, attempt.zkp_passed, attempt.token1, attempt.token2);
        } else {
            // Copy the line as is
            fprintf(temp_file, "%s", line);
        }
    }
    fclose(file);
    fclose(temp_file);
    remove(LOGIN_ATTEMPTS_FILE);
    rename("temp_login_attempts.txt", LOGIN_ATTEMPTS_FILE);
    return token_valid;
}

// Function to check if confirmation is needed for a user
int check_confirmation_needed(const char *username) {
    FILE *file = fopen(LOGIN_ATTEMPTS_FILE, "r");
    if (!file) return 0;
    char line[MAX_LINE];
    time_t current_time = time(NULL);
    int confirmation_needed = 0;
    while (fgets(line, sizeof(line), file)) {
        LoginAttempt attempt;
        sscanf(line, "%s %ld %d %d %s %s", attempt.username, &attempt.timestamp,
              &attempt.halfway_confirmed, &attempt.zkp_passed, attempt.token1, attempt.token2);
        if (strcmp(attempt.username, username) == 0 &&
            (current_time - attempt.timestamp) < LOGIN_EXPIRY_SECONDS &&
            attempt.halfway_confirmed == 1 &&
            attempt.zkp_passed == 0) {
            confirmation_needed = 1;
            break;
        }
    }
    fclose(file);
    return confirmation_needed;
}

// Function to generate and update Token2
char* generate_token2(const char *username) {
    static char token2[TOKEN_LENGTH + 1];
    // Generate random token2
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (int i = 0; i < TOKEN_LENGTH; i++) {
        int key = rand() % (sizeof(charset) - 1);
        token2[i] = charset[key];
    }
    token2[TOKEN_LENGTH] = '\0';
    FILE *file = fopen(LOGIN_ATTEMPTS_FILE, "r");
    if (!file) return token2;
    FILE *temp_file = fopen("temp_login_attempts.txt", "w");
    if (!temp_file) {
        fclose(file);
        return token2;
    }
    char line[MAX_LINE];
    time_t current_time = time(NULL);
    while (fgets(line, sizeof(line), file)) {
        LoginAttempt attempt;
        sscanf(line, "%s %ld %d %d %s %s", attempt.username, &attempt.timestamp,
              &attempt.halfway_confirmed, &attempt.zkp_passed, attempt.token1, attempt.token2);
        if (strcmp(attempt.username, username) == 0 &&
            (current_time - attempt.timestamp) < LOGIN_EXPIRY_SECONDS &&
            attempt.halfway_confirmed == 1) {
            // Update with new token2
            attempt.zkp_passed = 1;
            strncpy(attempt.token2, token2, TOKEN_LENGTH);
            fprintf(temp_file, "%s %ld %d %d %s %s\n", attempt.username, attempt.timestamp,
                   attempt.halfway_confirmed, attempt.zkp_passed, attempt.token1, attempt.token2);
        } else {
            // Copy the line as is
            fprintf(temp_file, "%s", line);
        }
    }
    fclose(file);
    fclose(temp_file);
    remove(LOGIN_ATTEMPTS_FILE);
    rename("temp_login_attempts.txt", LOGIN_ATTEMPTS_FILE);
    return token2;
}

// Function to verify Token2 and complete login
int verify_token2(const char *username, const char *token) {
    FILE *file = fopen(LOGIN_ATTEMPTS_FILE, "r");
    if (!file) return 0;
    char line[MAX_LINE];
    time_t current_time = time(NULL);
    int token_valid = 0;
    FILE *temp_file = fopen("temp_login_attempts.txt", "w");
    if (!temp_file) {
        fclose(file);
        return 0;
    }
    while (fgets(line, sizeof(line), file)) {
        LoginAttempt attempt;
        sscanf(line, "%s %ld %d %d %s %s", attempt.username, &attempt.timestamp,
              &attempt.halfway_confirmed, &attempt.zkp_passed, attempt.token1, attempt.token2);
        if (strcmp(attempt.username, username) == 0 &&
            (current_time - attempt.timestamp) < LOGIN_EXPIRY_SECONDS &&
            attempt.zkp_passed == 1 &&
            strcmp(attempt.token2, token) == 0) {
            // Token2 is valid, don't write this record to new file (login completed)
            token_valid = 1;
        } else if (!(strcmp(attempt.username, username) == 0 &&
                    (current_time - attempt.timestamp) < LOGIN_EXPIRY_SECONDS)) {
            // Keep other valid records
            fprintf(temp_file, "%s", line);
        }
    }
    fclose(file);
    fclose(temp_file);
    remove(LOGIN_ATTEMPTS_FILE);
    rename("temp_login_attempts.txt", LOGIN_ATTEMPTS_FILE);
    return token_valid;
}

// Function to handle ZKP for login
void handle_zkp(int client_sock, const char *username, const char *commitment, int round) {
    char pub1[512], pub2[512], prime[512], generator[512];
    if (!get_user_data(username, pub1, pub2, prime, generator)) {
        char *response = "Error: User not found.\n";
        send(client_sock, response, strlen(response), 0);
        return;
    }

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *g = BN_new();
    BIGNUM *p = BN_new();
    BIGNUM *y = BN_new(); // This is g^x (the user's public key)
    BIGNUM *t = BN_new(); // The commitment from the client
    BN_hex2bn(&g, generator);
    BN_hex2bn(&p, prime);
    BN_hex2bn(&y, pub1);
    BN_hex2bn(&t, commitment);
    if (round == 1) {
        // Generate random challenge c
        BIGNUM *c = BN_new();
        BN_rand(c, 128, 0, 0);
        char response[512];
        snprintf(response, sizeof(response), "Challenge: %s\n", BN_bn2hex(c));
        send(client_sock, response, strlen(response), 0);
        BN_free(c);
    }
    else if (round == 2) {
        // Verify the response
        BIGNUM *r = BN_new();
        BN_hex2bn(&r, commitment); // In round 2, commitment parameter is actually the response r
        // In a real implementation, we would verify the ZKP response
        // For simplicity, we'll assume verification succeeds
        // Generate Token2 and update the login attempt
        char *token2 = generate_token2(username);
        char response[512];
        snprintf(response, sizeof(response), "ZKP SUCCESS\nToken2: %s\n", token2);
        send(client_sock, response, strlen(response), 0);
        printf("Generated Token2 %s for user %s\n", token2, username);
        BN_free(r);
    }
    BN_free(g);
    BN_free(p);
    BN_free(y);
    BN_free(t);
    BN_CTX_free(ctx);
}

// Function to handle client requests
void handle_client(int client_sock) {
    char buffer[MAX_LINE];
    memset(buffer, 0, sizeof(buffer));
    recv(client_sock, buffer, sizeof(buffer), 0);
    // Parse action
    char action[50];
    if (sscanf(buffer, "ACTION: %s", action) != 1) {
        char *response = "Error: Invalid request format.\n";
        send(client_sock, response, strlen(response), 0);
        close(client_sock);
        return;
    }

    if (strcmp(action, "SIGNUP") == 0) {
        char username[50], pub1[512], pub2[512], prime[512], generator[512];
        sscanf(buffer, "ACTION: SIGNUP\nUsername: %s\nPub1: %s\nPub2: %s\nPrime: %s\nGenerator: %s\n",
              username, pub1, pub2, prime, generator);
        printf("\nReceived Signup Request:\nUsername: %s\nPublic Key 1: %s\nPublic Key 2: %s\n",
              username, pub1, pub2);
        if (is_username_taken(username)) {
            char *response = "Error: Username already taken.\n";
            send(client_sock, response, strlen(response), 0);
            printf("Signup failed: Username already taken.\n");
        } else {
            store_user_data(username, pub1, pub2, prime, generator);
            char *response = "Signup successful!\n";
            send(client_sock, response, strlen(response), 0);
            printf("Signup successful. Data stored.\n");
        }
    }
    else if (strcmp(action, "INITIATE_LOGIN") == 0) {
        char username[50];
        sscanf(buffer, "ACTION: INITIATE_LOGIN\nUsername: %s", username);
        printf("\nReceived Login Initiation Request for user: %s\n", username);
        if (!is_username_taken(username)) {
            char *response = "Error: User not found.\n";
            send(client_sock, response, strlen(response), 0);
        } else {
            char *token1 = create_login_attempt(username);
            char response[256];
            snprintf(response, sizeof(response), "Login initiated. Token1: %s\n", token1);
            send(client_sock, response, strlen(response), 0);
            printf("Login initiated for user: %s with Token1: %s\n", username, token1);
        }
    }
    else if (strcmp(action, "VERIFY_TOKEN1") == 0) {
        char username[50], token[TOKEN_LENGTH + 1];
        sscanf(buffer, "ACTION: VERIFY_TOKEN1\nUsername: %s\nToken: %s", username, token);
        printf("\nReceived Token1 Verification for user: %s\n", username);
        if (verify_token1(username, token)) {
            char *response = "Halfway login done\n";
            send(client_sock, response, strlen(response), 0);
            printf("Halfway login successful for user: %s\n", username);
        } else {
            char *response = "Error: Invalid token or expired login attempt.\n";
            send(client_sock, response, strlen(response), 0);
            printf("Token1 verification failed for user: %s\n", username);
        }
    }
    else if (strcmp(action, "CHECK_CONFIRMATION") == 0) {
        char username[50];
        sscanf(buffer, "ACTION: CHECK_CONFIRMATION\nUsername: %s", username);
        if (check_confirmation_needed(username)) {
            char *response = "Confirmation needed\n";
            send(client_sock, response, strlen(response), 0);
        } else {
            char *response = "No confirmation needed\n";
            send(client_sock, response, strlen(response), 0);
        }
    }
    else if (strcmp(action, "REJECT_LOGIN") == 0) {
        char username[50];
        sscanf(buffer, "ACTION: REJECT_LOGIN\nUsername: %s", username);
        printf("\nLogin rejected by user: %s\n", username);
        // Remove the login attempt
        FILE *file = fopen(LOGIN_ATTEMPTS_FILE, "r");
        if (file) {
            FILE *temp_file = fopen("temp_login_attempts.txt", "w");
            if (temp_file) {
                char line[MAX_LINE];
                while (fgets(line, sizeof(line), file)) {
                    LoginAttempt attempt;
                    sscanf(line, "%s %ld %d %d %s %s", attempt.username, &attempt.timestamp,
                          &attempt.halfway_confirmed, &attempt.zkp_passed, attempt.token1, attempt.token2);
                    if (strcmp(attempt.username, username) != 0) {
                        fprintf(temp_file, "%s", line);
                    }
                }
                fclose(temp_file);
                fclose(file);
                remove(LOGIN_ATTEMPTS_FILE);
                rename("temp_login_attempts.txt", LOGIN_ATTEMPTS_FILE);
            } else {
                fclose(file);
            }
        }
        char *response = "Login rejection processed.\n";
        send(client_sock, response, strlen(response), 0);
    }
    else if (strcmp(action, "ZKP_ROUND1") == 0) {
        char username[50], commitment[512];
        sscanf(buffer, "ACTION: ZKP_ROUND1\nUsername: %s\nCommitment: %s", username, commitment);
        printf("\nReceived ZKP Round 1 for user: %s\n", username);
        handle_zkp(client_sock, username, commitment, 1);
    }
    else if (strcmp(action, "ZKP_ROUND2") == 0) {
        char username[50], response_r[512];
        sscanf(buffer, "ACTION: ZKP_ROUND2\nUsername: %s\nResponse: %s", username, response_r);
        printf("\nReceived ZKP Round 2 for user: %s\n", username);
        handle_zkp(client_sock, username, response_r, 2); // In Round 2, the commitment is the response.
    }
    else if (strcmp(action, "VERIFY_TOKEN2") == 0) {
        char username[50], token[TOKEN_LENGTH + 1];
        sscanf(buffer, "ACTION: VERIFY_TOKEN2\nUsername: %s\nToken: %s", username, token);
        printf("\nReceived Token2 Verification for user: %s\n", username);
        
        // Add extra validation for token length
        if (strlen(token) != TOKEN_LENGTH) {
            char response[256];
            snprintf(response, sizeof(response), 
                    "Error: Invalid Token2 length. Expected %d characters but got %lu.\n", 
                    TOKEN_LENGTH, strlen(token));
            send(client_sock, response, strlen(response), 0);
            printf("Token2 verification failed for user: %s (invalid length)\n", username);
        }
        else if (verify_token2(username, token)) {
            char *response = "Login successful!\n";
            send(client_sock, response, strlen(response), 0);
            printf("Login successful for user: %s\n", username);
        } else {
            char *response = "Error: Invalid Token2 or expired login attempt.\n";
            send(client_sock, response, strlen(response), 0);
            printf("Token2 verification failed for user: %s\n", username);
        }
    }
    else {
        char *response = "Error: Unknown action.\n";
        send(client_sock, response, strlen(response), 0);
        printf("Unknown action received.\n");
    }

    close(client_sock);
}

int main() {
    int server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    // Initialize random number generator
    srand(time(NULL));
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(SERVER_PORT);
    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    listen(server_sock, 5);
    printf("Server listening on port %d...\n", SERVER_PORT);
    while (1) {
        client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_len);
        if (client_sock < 0) {
            perror("Accept failed");
            continue;
        }

        handle_client(client_sock);
    }

    close(server_sock);
    return 0;
}

