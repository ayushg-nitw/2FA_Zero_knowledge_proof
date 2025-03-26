#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <time.h>

#define PRIME_BITS 256 // Size of prime number
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8080
#define TOKEN_LENGTH 16

// Generate key pair for trusted device (used for signatures)
void generate_device_keypair(EVP_PKEY **key_pair) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    EVP_PKEY_keygen(ctx, key_pair);
    EVP_PKEY_CTX_free(ctx);
}

// Sign a message with the device's private key
unsigned char* sign_message(EVP_PKEY *key, const unsigned char *msg, size_t msg_len, size_t *sig_len) {
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    EVP_SignInit(md_ctx, EVP_sha256());
    EVP_SignUpdate(md_ctx, msg, msg_len);
    unsigned char *sig = malloc(EVP_PKEY_size(key));
    EVP_SignFinal(md_ctx, sig, sig_len, key);
    EVP_MD_CTX_free(md_ctx);
    return sig;
}

// Convert password to a secret key (binary representation)
BIGNUM* password_to_secret_key(const char *password) {
    BIGNUM *secret = BN_new();
    BN_bin2bn((const unsigned char*)password, strlen(password), secret);
    return secret;
}

// Generate a random secret key
BIGNUM* generate_random_secret_key() {
    BIGNUM *secret = BN_new();
    BN_rand(secret, PRIME_BITS, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
    return secret;
}

// Compute public key (g^x mod p)
BIGNUM* compute_public_key(BIGNUM *g, BIGNUM *x, BIGNUM *p, BN_CTX *ctx) {
    BIGNUM *gx = BN_new();
    BN_mod_exp(gx, g, x, p, ctx);
    return gx;
}

// Send data over TCP and wait for a response
void send_to_server(const char *data, char *response, size_t resp_size) {
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

    send(sock, data, strlen(data), 0);
    // Receive response from server
    memset(response, 0, resp_size);
    recv(sock, response, resp_size, 0);
    close(sock);
}

// Function to initiate login and get Token1
char* initiate_login(const char *username, EVP_PKEY *device_key) {
    char message[512];
    snprintf(message, sizeof(message), "ACTION: INITIATE_LOGIN\nUsername: %s\n", username);
    size_t sig_len;
    unsigned char *signature = sign_message(device_key, (const unsigned char*)message, strlen(message), &sig_len);
    // Convert signature to hex for transmission
    char *sig_hex = malloc(sig_len * 2 + 1);
    for (size_t i = 0; i < sig_len; i++) {
        sprintf(sig_hex + (i * 2), "%02x", signature[i]);
    }

    sig_hex[sig_len * 2] = '\0';
    char request[1024];
    snprintf(request, sizeof(request), "%sSIGNATURE: %s\n", message, sig_hex);
    static char token1[TOKEN_LENGTH + 1];
    memset(token1, 0, sizeof(token1));
    char response[256];
    send_to_server(request, response, sizeof(response));
    printf("Server Response: %s\n", response);
    // Extract token1 from server response
    if (strstr(response, "Token1:") != NULL) {
        sscanf(strstr(response, "Token1:"), "Token1: %s", token1);
        printf("\n=== LOGIN TOKEN1: %s ===\n", token1);
        printf("Enter this token on the untrusted device to initiate login.\n");
    }

    free(signature);
    free(sig_hex);
    return token1;
}

// Function to check for login confirmation requests
int check_login_confirmation(const char *username, EVP_PKEY *device_key) {
    char message[512];
    snprintf(message, sizeof(message), "ACTION: CHECK_CONFIRMATION\nUsername: %s\n", username);
    size_t sig_len;
    unsigned char *signature = sign_message(device_key, (const unsigned char*)message, strlen(message), &sig_len);
    char *sig_hex = malloc(sig_len * 2 + 1);
    for (size_t i = 0; i < sig_len; i++) {
        sprintf(sig_hex + (i * 2), "%02x", signature[i]);
    }

    sig_hex[sig_len * 2] = '\0';
    char request[1024];
    snprintf(request, sizeof(request), "%sSIGNATURE: %s\n", message, sig_hex);
    char response[256];
    send_to_server(request, response, sizeof(response));
    int confirmation_needed = (strstr(response, "Confirmation needed") != NULL);
    free(signature);
    free(sig_hex);
    return confirmation_needed;
}

// Function to perform zero-knowledge proof of discrete logarithm and generate Token2
char* perform_zkp_login(const char *username, const char *password, BIGNUM *g, BIGNUM *p, EVP_PKEY *device_key) {
    BN_CTX *ctx = BN_CTX_new();
    // Compute user's secret key from password
    BIGNUM *x = password_to_secret_key(password);
    // ZKP Round 1: Generate random k and compute t = g^k mod p
    BIGNUM *k = BN_new();
    BN_rand(k, PRIME_BITS, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
    BIGNUM *t = BN_new();
    BN_mod_exp(t, g, k, p, ctx);
    // Send t to server
    char message[1024];
    snprintf(message, sizeof(message),
            "ACTION: ZKP_ROUND1\nUsername: %s\nCommitment: %s\n",
            username, BN_bn2hex(t));
    size_t sig_len;
    unsigned char *signature = sign_message(device_key, (const unsigned char*)message, strlen(message), &sig_len);
    // Convert signature to hex for transmission
    char *sig_hex = malloc(sig_len * 2 + 1);
    for (size_t i = 0; i < sig_len; i++) {
        sprintf(sig_hex + (i * 2), "%02x", signature[i]);
    }

    sig_hex[sig_len * 2] = '\0';
    char request[2048];
    snprintf(request, sizeof(request), "%sSIGNATURE: %s\n", message, sig_hex);
    char response[512];
    send_to_server(request, response, sizeof(response));
    // Extract challenge from server response
    char challenge_hex[256];
    sscanf(response, "Challenge: %s", challenge_hex);
    BIGNUM *c = BN_new();
    BN_hex2bn(&c, challenge_hex);
    // ZKP Round 2: Compute response r = k - c*x mod (p-1)
    BIGNUM *p_minus_1 = BN_new();
    BN_copy(p_minus_1, p);
    BN_sub_word(p_minus_1, 1);
    BIGNUM *cx = BN_new();
    BN_mod_mul(cx, c, x, p_minus_1, ctx);
    BIGNUM *r = BN_new();
    BN_mod_sub(r, k, cx, p_minus_1, ctx);
    // Send response to server
    snprintf(message, sizeof(message),
            "ACTION: ZKP_ROUND2\nUsername: %s\nResponse: %s\n",
            username, BN_bn2hex(r));
    free(signature);
    free(sig_hex);
    signature = sign_message(device_key, (const unsigned char*)message, strlen(message), &sig_len);
    // Convert signature to hex for transmission
    sig_hex = malloc(sig_len * 2 + 1);
    for (size_t i = 0; i < sig_len; i++) {
        sprintf(sig_hex + (i * 2), "%02x", signature[i]);
    }

    sig_hex[sig_len * 2] = '\0';
    snprintf(request, sizeof(request), "%sSIGNATURE: %s\n", message, sig_hex);
    memset(response, 0, sizeof(response));
    send_to_server(request, response, sizeof(response));
    printf("Server Response: %s\n", response);
    static char token2[TOKEN_LENGTH + 1];
    memset(token2, 0, sizeof(token2));
    // Extract token2 if ZKP was successful
    if (strstr(response, "Token2:") != NULL) {
        sscanf(strstr(response, "Token2:"), "Token2: %s", token2);
        printf("\n=== LOGIN TOKEN2: %s ===\n", token2);
        printf("Enter this token on the untrusted device to complete login.\n");
    } else {
        printf("Failed to obtain Token2. ZKP may have failed.\n");
    }

    // Free memory
    BN_free(x);
    BN_free(k);
    BN_free(t);
    BN_free(c);
    BN_free(p_minus_1);
    BN_free(cx);
    BN_free(r);
    BN_CTX_free(ctx);
    free(signature);
    free(sig_hex);
    return token2;
}

// Function to handle signup
void signup(const char *username, const char *password) {
    BN_CTX *ctx = BN_CTX_new();
    // Generate prime p and generator g
    BIGNUM *p = BN_new(), *g = BN_new();
    BN_generate_prime_ex(p, PRIME_BITS, 1, NULL, NULL, NULL);
    BN_set_word(g, 2);
    // Create secret keys
    BIGNUM *secret1 = password_to_secret_key(password);
    BIGNUM *secret2 = generate_random_secret_key();
    // Compute public keys
    BIGNUM *public1 = compute_public_key(g, secret1, p, ctx);
    BIGNUM *public2 = compute_public_key(g, secret2, p, ctx);
    // Print secret and public keys
    printf("\nGenerated Keys:\n");
    printf("Secret Key 1 (from password): %s\n", BN_bn2hex(secret1));
    printf("Secret Key 2 (random): %s\n", BN_bn2hex(secret2));
    printf("Public Key 1: %s\n", BN_bn2hex(public1));
    printf("Public Key 2: %s\n", BN_bn2hex(public2));
    // Send data to server
    char request[2048];
    snprintf(request, sizeof(request),
            "ACTION: SIGNUP\nUsername: %s\nPub1: %s\nPub2: %s\nPrime: %s\nGenerator: %s\n",
            username, BN_bn2hex(public1), BN_bn2hex(public2), BN_bn2hex(p), BN_bn2hex(g));
    char response[256];
    send_to_server(request, response, sizeof(response));
    printf("Server Response: %s\n", response);
    // Store the keys locally for trusted device
    if (strstr(response, "successful") != NULL) {
        FILE *keyfile = fopen("device_keys.txt", "a");
        if (keyfile) {
            fprintf(keyfile, "%s %s %s %s %s\n",
                    username, BN_bn2hex(secret1), BN_bn2hex(secret2), BN_bn2hex(p), BN_bn2hex(g));
            fclose(keyfile);
            printf("Keys saved locally.\n");
        }
    }
    // Free memory
    BN_free(p);
    BN_free(g);
    BN_free(secret1);
    BN_free(secret2);
    BN_free(public1);
    BN_free(public2);
    BN_CTX_free(ctx);
}

int main() {
    int choice;
    char username[50], password[50];
    // Generate device keypair for signing messages
    EVP_PKEY *device_key = NULL;
    generate_device_keypair(&device_key);
    printf("1. Register new account\n");
    printf("2. Login\n");
    printf("Choose an option: ");
    scanf("%d", &choice);
    getchar(); // consume newline
    printf("Enter username: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = 0; // Remove newline
    if (choice == 1) {
        printf("Enter password: ");
        fgets(password, sizeof(password), stdin);
        password[strcspn(password, "\n")] = 0; // Remove newline
        signup(username, password);
    }
    else if (choice == 2) {
        printf("Enter password: ");
        fgets(password, sizeof(password), stdin);
        password[strcspn(password, "\n")] = 0; // Remove newline
        // Step 1: Initiate login and get Token1
        char *token1 = initiate_login(username, device_key);
        printf("Waiting for user to enter Token1 on untrusted device...\n");
        // Step 2: Check for confirmation request (poll more times)
        int confirmation_needed = 0;
        for (int i = 0; i < 60 && !confirmation_needed; i++) {
            sleep(2); // Wait 2 seconds between polls
            confirmation_needed = check_login_confirmation(username, device_key);
            printf("Polling for confirmation requests (%d/60)...\r", i+1);
            fflush(stdout);
        }
        printf("\n");
        
        if (!confirmation_needed) {
            printf("No login confirmation request received within timeout.\n");
            printf("Do you want to check again? (Yes/No): ");
            char retry[10];
            fgets(retry, sizeof(retry), stdin);
            retry[strcspn(retry, "\n")] = 0;
            
            if (strncmp(retry, "Yes", 3) == 0) {
                confirmation_needed = check_login_confirmation(username, device_key);
                printf("Manual check result: %s\n", 
                      confirmation_needed ? "Confirmation needed" : "No confirmation needed");
            }
        }
        
        if (confirmation_needed) {
            // Step 3: Ask user to confirm login
            printf("Halfway login detected! Type Yes or No to confirm: ");
            char choice[10];
            fgets(choice, sizeof(choice), stdin);
            choice[strcspn(choice, "\n")] = 0;
            
            if (strncmp(choice, "Yes", 3) == 0) {
                // Read stored params for this user
                FILE *keyfile = fopen("device_keys.txt", "r");
                if (!keyfile) {
                    printf("Error: No locally stored keys found.\n");
                    return 1;
                }

                char line[1024];
                int found = 0;
                BIGNUM *p = BN_new();
                BIGNUM *g = BN_new();
                while (fgets(line, sizeof(line), keyfile)) {
                    char stored_username[50];
                    char p_hex[256], g_hex[256];
                    char secret1_hex[256], secret2_hex[256];
                    sscanf(line, "%s %s %s %s %s",
                          stored_username, secret1_hex, secret2_hex, p_hex, g_hex);
                    if (strcmp(stored_username, username) == 0) {
                        BN_hex2bn(&p, p_hex);
                        BN_hex2bn(&g, g_hex);
                        found = 1;
                        break;
                    }
                }
                fclose(keyfile);
                if (!found) {
                    printf("Error: User not found in local storage.\n");
                    BN_free(p);
                    BN_free(g);
                    return 1;
                }

                // Step 4: Perform ZKP and get Token2
                char *token2 = perform_zkp_login(username, password, g, p, device_key);
                printf("\nPlease copy the complete Token2 to the untrusted device.\n");
                printf("Token2 length must be exactly %d characters.\n", TOKEN_LENGTH);
                printf("Press Enter when done...");
                getchar();
                
                BN_free(p);
                BN_free(g);
            } else {
                // Send rejection
                char message[512];
                snprintf(message, sizeof(message), "ACTION: REJECT_LOGIN\nUsername: %s\n", username);
                size_t sig_len;
                unsigned char *signature = sign_message(device_key, (const unsigned char*)message, strlen(message), &sig_len);
                char *sig_hex = malloc(sig_len * 2 + 1);
                for (size_t i = 0; i < sig_len; i++) {
                    sprintf(sig_hex + (i * 2), "%02x", signature[i]);
                }
                sig_hex[sig_len * 2] = '\0';
                char request[1024];
                snprintf(request, sizeof(request), "%sSIGNATURE: %s\n", message, sig_hex);
                char response[256];
                send_to_server(request, response, sizeof(response));
                printf("Login rejected.\n");
                free(signature);
                free(sig_hex);
            }
        } else {
            printf("No login confirmation request received.\n");
        }
    }
    EVP_PKEY_free(device_key);
    return 0;
}

