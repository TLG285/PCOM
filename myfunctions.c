#include <stdlib.h> /* exit, atoi, malloc, free */
#include <stdio.h>
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include "myfunctions.h"
#include "helpers.h"
#include "parson.h"
#include "requests.h"
#define FIELD_SIZE 2000

void print_movie_details(char *response)
{
    char *json_text = extract_json_payload(response);
    JSON_Value *root_value = json_parse_string(json_text);
    JSON_Object *root_object = json_value_get_object(root_value);

    const char *title = json_object_get_string(root_object, "title");
    int year = json_object_get_number(root_object, "year");
    const char *description = json_object_get_string(root_object, "description");
    const char *rating = json_object_get_string(root_object, "rating");

    printf("SUCCESS: Detalii film\n");
    printf("title: %s\n", title);
    printf("year: %d\n", year);
    printf("description: %s\n", description);
    printf("rating: %s\n", rating);

    json_value_free(root_value);
}

void print_collection(char *response)
{
    char *json_text = extract_json_payload(response);
    JSON_Value *root_value = json_parse_string(json_text);
    JSON_Object *root_object = json_value_get_object(root_value);

    // Extrage title și owner (obligatoriu pentru checker)
    const char *title = json_object_get_string(root_object, "title");
    const char *owner = json_object_get_string(root_object, "owner");

    printf("title: %s\n", title);
    printf("owner: %s\n", owner);

    // Extrage și afișează filmele cu formatul cerut
    JSON_Array *movies = json_object_get_array(root_object, "movies");
    for (size_t i = 0; i < json_array_get_count(movies); i++)
    {
        JSON_Object *movie = json_array_get_object(movies, i);
        int movie_id = (int)json_object_get_number(movie, "id");
        const char *movie_title = json_object_get_string(movie, "title");

        printf("#%d: %s\n", movie_id, movie_title);
    }

    json_value_free(root_value);
}

void print_collections(char *response)
{
    char *json_text = extract_json_payload(response);
    JSON_Value *root_value = json_parse_string(json_text);
    JSON_Object *root_object = json_value_get_object(root_value);
    JSON_Array *collections = json_object_get_array(root_object, "collections");

    for (size_t i = 0; i < json_array_get_count(collections); i++)
    {
        JSON_Object *collection = json_array_get_object(collections, i);
        const char *title = json_object_get_string(collection, "title");
        int id = (int)json_object_get_number(collection, "id");
        printf("#%zu: %s\n", id, title);
    }

    json_value_free(root_value);
}

void print_movies_array(char *response)
{
    char *payload = extract_json_payload(response);
    JSON_Value *root_val = json_parse_string(payload);
    if (root_val == NULL)
    {
        fprintf(stderr, "Eroare: JSON invalid.\n");
        return NULL;
    }

    JSON_Object *root_obj = json_value_get_object(root_val);
    JSON_Array *movies_array = json_object_get_array(root_obj, "movies");

    if (movies_array == NULL)
    {
        fprintf(stderr, "Eroare: nu există câmpul \"movies\".\n");
        json_value_free(root_val);
        return NULL;
    }

    printf("SUCCESS: Lista filmelor:\n");
    size_t movies_count = json_array_get_count(movies_array);
    for (size_t i = 0; i < movies_count; ++i)
    {
        JSON_Object *movie = json_array_get_object(movies_array, i);
        if (movie)
        {
            int id = (int)json_object_get_number(movie, "id");
            const char *title = json_object_get_string(movie, "title");
            if (title)
            {
                printf("#%d %s\n", id, title);
            }
        }
    }
}

/// @brief functie care intoarece statusul raspunsuslui din partea serverului
/// @param response raspunsul primit de la server
/// @return ERROR/ SUCCESS/ NULL daca nu s-a primit raspuns
char *extract_JWT(char *response)
{
    char *json_payload = extract_json_payload(response);
    JSON_Value *root_val = json_parse_string(json_payload);
    if (root_val == NULL)
    {
        fprintf(stderr, "Eroare: JSON invalid.\n");
        return NULL;
    }
    JSON_Object *root_obj = json_value_get_object(root_val);
    const char *token = json_object_get_string(root_obj, "token");
    if (token == NULL)
    {
        fprintf(stderr, "Token lipsă sau invalid.\n");
        json_value_free(root_val);
        return NULL;
    }
    return token;
}

char *extract_sv_resp_status(char *response)
{
    char *json_payload = extract_json_payload(response);
    JSON_Value *root_val = json_parse_string(json_payload);
    if (root_val == NULL)
    {
        fprintf(stderr, "Eroare: JSON invalid.\n");
        return NULL;
    }
    JSON_Object *root_obj = json_value_get_object(root_val);

    const char *first_key = json_object_get_name(root_obj, 0);
    if (first_key == NULL)
    {
        json_value_free(root_val);
        return NULL;
    }

    return first_key;
}

/// @brief functie care extrage dintr-un raspuns primit de la un server payload-ul
/// @param response
/// @return
char *extract_json_payload(const char *response)
{
    const char *json_start = strstr(response, "\r\n\r\n");
    if (!json_start)
    {
        return NULL; // delimitator nu găsit
    }

    // JSON-ul începe după "\r\n\r\n"
    json_start += 4;

    char *payload = strdup(json_start); // strdup alocă și copiază
    return payload;
}

/// @brief functie care extrage cookie-ul dintr-un raspuns primit de la un server
/// @param response
/// @return
char *extract_cookie(char *response)
{
    char *cookie = malloc(sizeof(char));
    char *start = strstr(response, "Set-Cookie: ");
    if (start)
    {
        start += strlen("Set-Cookie: ");
        char *end = strstr(start, ";");
        if (end)
        {
            int len = end - start;
            cookie = malloc(len + 1);
            strncpy(cookie, start, len);
            cookie[len] = '\0';
        }
    }
    return cookie;
}
/// @brief function to login to a server
/// @return the response from the server
char *login_admin()
{
    int sockfd;
    // datele de logare cu parson:
    char username[FIELD_SIZE], password[FIELD_SIZE];
    printf("username=");
    scanf("%s", username);
    printf("password=");
    scanf("%s", password);

    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);

    json_object_set_string(root_object, "username", username);
    json_object_set_string(root_object, "password", password);

    // Serializează JSON-ul într-un string
    char *serialized_body = json_serialize_to_string_pretty(root_value);

    // Pregătește body_data pentru compute_post_request
    char **body_data = malloc(BUFLEN);
    body_data[0] = strdup(serialized_body);

    // Login into server
    sockfd = open_connection(SERVERADDR, PORT, AF_INET, SOCK_STREAM, 0);
    char *message = compute_post_request(SVPORT, "/api/v1/tema/admin/login",
                                         "application/json", body_data, 1,
                                         NULL, 0, NULL, 0);
    // printf("\nmesajul trimis catre server:\n%s\n", message);
    send_to_server(sockfd, message);

    char *response = strdup(receive_from_server(sockfd));

    // printf("\nraspunsul primit de la server:\n %s\n", response);
    close(sockfd);
    free(message);
    free(body_data[0]);
    free(body_data);
    json_free_serialized_string(serialized_body);
    json_value_free(root_value);
    return response;
}

/// @brief functie care adauga un nou user
/// @param cookies
/// @param cookies_number
/// @return
char *add_user(char **cookies, int cookies_number)
{
    int sockfd;
    char username[FIELD_SIZE], password[FIELD_SIZE];
    printf("username=");
    scanf("%s", username);
    getchar();

    if (strstr(username, " ") != NULL)
    {
        return "error";
    }
    printf("password=");
    scanf("%s", password);
    getchar();
    if (strstr(password, " ") != NULL)
    {
        return "error";
    }
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);

    json_object_set_string(root_object, "username", username);
    json_object_set_string(root_object, "password", password);

    // Serializează JSON-ul într-un string
    char *serialized_body = json_serialize_to_string_pretty(root_value);

    // Pregătește body_data pentru compute_post_request
    char **body_data = malloc(BUFLEN);
    body_data[0] = strdup(serialized_body);

    // Login into server
    sockfd = open_connection(SERVERADDR, PORT, AF_INET, SOCK_STREAM, 0);
    char *message = compute_post_request(SVPORT, "/api/v1/tema/admin/users",
                                         "application/json", body_data, 1,
                                         cookies, cookies_number, NULL, 0);
    // printf("\nmesajul trimis catre server:\n%s\n", message);
    send_to_server(sockfd, message);
    char *response = receive_from_server(sockfd);
    // printf("%s\n", response);
    close(sockfd);
    free(message);
    free(body_data[0]);
    free(body_data);
    json_free_serialized_string(serialized_body);
    json_value_free(root_value);
    return response;
}

/// @brief functie care adauga un nou user
/// @param cookies
/// @param cookies_number
/// @return
char *get_users(char **cookies, int cookies_number)
{
    int sockfd;
    // Login into server
    sockfd = open_connection(SERVERADDR, PORT, AF_INET, SOCK_STREAM, 0);
    char *message = compute_get_request(SVPORT, "/api/v1/tema/admin/users",
                                        NULL, cookies, cookies_number, NULL, 0);
    // printf("\nmesajul trimis catre server:\n%s\n", message);
    send_to_server(sockfd, message);
    char *response = receive_from_server(sockfd);
    // afisam userii primiti
    JSON_Value *root_val = json_parse_string(extract_json_payload(response));
    if (root_val == NULL)
    {
        fprintf(stderr, "Eroare: JSON invalid.\n");
        return NULL;
    }

    JSON_Object *root_obj = json_value_get_object(root_val);
    JSON_Array *users_array = json_object_get_array(root_obj, "users");

    if (users_array == NULL)
    {
        fprintf(stderr, "Eroare: nu există câmpul \"users\".\n");
        json_value_free(root_val);
        return NULL;
    }

    printf("SUCCESS: Lista utilizatorilor:\n");
    size_t user_count = json_array_get_count(users_array);
    for (size_t i = 0; i < user_count; ++i)
    {
        JSON_Object *user = json_array_get_object(users_array, i);
        if (user)
        {
            int id = (int)json_object_get_number(user, "id");
            const char *username = json_object_get_string(user, "username");
            const char *password = json_object_get_string(user, "password");
            if (username && password)
            {
                printf("#%d %s:%s\n", id, username, password);
            }
        }
    }

    json_value_free(root_val);
    close(sockfd);
    free(message);
    return response;
}

char *delete_user(char **cookies, int cookies_number)
{
    int sockfd;
    char username[FIELD_SIZE];
    printf("username=");
    scanf("%s", username);
    // Login into server
    sockfd = open_connection(SERVERADDR, PORT, AF_INET, SOCK_STREAM, 0);
    char *url = calloc(FIELD_SIZE, 1);
    sprintf(url, "/api/v1/tema/admin/users/%s", username);
    // printf("\nurl: %s\n", url);
    char *message = compute_delete_request(SVPORT, url, "application/json",
                                           cookies, cookies_number, NULL, 0);
    // printf("\nmesajul trimis catre server:\n%s\n", message);
    send_to_server(sockfd, message);
    char *response = receive_from_server(sockfd);
    // printf("\nraspunsul de la server:\n%s\n", response);
    close(sockfd);
    free(url);
    free(message);
    return response;
}

char *logout_admin(char **cookies, int cookies_number)
{
    int sockfd;
    // Login into server
    sockfd = open_connection(SERVERADDR, PORT, AF_INET, SOCK_STREAM, 0);
    char *message = compute_get_request(SVPORT, "/api/v1/tema/admin/logout",
                                        NULL, cookies, cookies_number, NULL, 0);
    // printf("\nmesajul trimis catre server:\n%s\n", message);
    send_to_server(sockfd, message);
    char *response = receive_from_server(sockfd);
    // printf("%s\n", response);
    close(sockfd);
    free(message);
    return response;
}

char *login(char **cookies, int cookies_number)
{
    int sockfd;
    // datele de logare cu parson:
    char admin_username[FIELD_SIZE], username[FIELD_SIZE], password[FIELD_SIZE];
    printf("admin_username=");
    scanf("%s", admin_username);
    printf("username=");
    scanf("%s", username);
    printf("password=");
    scanf("%s", password);

    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);

    json_object_set_string(root_object, "admin_username", admin_username);
    json_object_set_string(root_object, "username", username);
    json_object_set_string(root_object, "password", password);

    // Serializează JSON-ul într-un string
    char *serialized_body = json_serialize_to_string_pretty(root_value);

    // Pregătește body_data pentru compute_post_request
    char **body_data = malloc(BUFLEN);
    body_data[0] = strdup(serialized_body);

    // Login into server
    sockfd = open_connection(SERVERADDR, PORT, AF_INET, SOCK_STREAM, 0);
    char *message = compute_post_request(SVPORT, "/api/v1/tema/user/login",
                                         "application/json", body_data, 1,
                                         cookies, cookies_number, NULL, 0);
    // printf("\nmesajul trimis catre server:\n%s\n", message);
    send_to_server(sockfd, message);

    char *response = strdup(receive_from_server(sockfd));
    close(sockfd);
    free(message);
    free(body_data[0]);
    free(body_data);
    json_free_serialized_string(serialized_body);
    json_value_free(root_value);
    return response;
}

char *logout(char **cookies, int cookies_number)
{
    int sockfd;
    sockfd = open_connection(SERVERADDR, PORT, AF_INET, SOCK_STREAM, 0);
    char *message = compute_get_request(SVPORT, "/api/v1/tema/user/logout",
                                        NULL, cookies, cookies_number, NULL, 0);
    // printf("\nmesajul trimis catre server:\n%s\n", message);
    send_to_server(sockfd, message);
    char *response = receive_from_server(sockfd);
    // printf("%s\n", response);
    close(sockfd);
    free(message);
    return response;
}

//__________________________________________MOVIES______________________________________________________

char *get_access(char **cookies, int cookies_number)
{
    int sockfd;
    // Login into server
    sockfd = open_connection(SERVERADDR, PORT, AF_INET, SOCK_STREAM, 0);
    char *message = compute_get_request(SVPORT, "/api/v1/tema/library/access",
                                        NULL, cookies, cookies_number, NULL, 0);
    // printf("\nmesajul trimis catre server:\n%s\n", message);
    send_to_server(sockfd, message);
    char *response = receive_from_server(sockfd);
    // printf("%s\n", response);
    close(sockfd);
    free(message);
    return response;
}

char *get_movies(char **cookies, int cookies_number, char **jwt, int jwt_number)
{
    int sockfd;
    // Login into server
    sockfd = open_connection(SERVERADDR, PORT, AF_INET, SOCK_STREAM, 0);
    char *message = compute_get_request(SVPORT, "/api/v1/tema/library/movies",
                                        NULL, cookies, cookies_number, jwt, jwt_number);
    // printf("\nmesajul trimis catre server:\n%s\n", message);
    send_to_server(sockfd, message);
    char *response = receive_from_server(sockfd);
    // printf("raspunsul primit de la server: \n%s\n", response);
    close(sockfd);
    free(message);
    return response;
}

char *get_movie(char **cookies, int cookies_number, char **jwt, int jwt_number)
{
    int sockfd;
    int id = 0;
    printf("id= \n");
    scanf("%d", &id);
    // Login into server
    sockfd = open_connection(SERVERADDR, PORT, AF_INET, SOCK_STREAM, 0);
    char *url = calloc(FIELD_SIZE, 1);
    sprintf(url, "/api/v1/tema/library/movies/%d", id);
    char *message = compute_get_request(SVPORT, url, NULL, cookies,
                                        cookies_number, jwt, jwt_number);
    // printf("\nmesajul trimis catre server:\n%s\n", message);
    send_to_server(sockfd, message);
    char *response = receive_from_server(sockfd);
    // printf("raspunsul primit de la server: \n%s\n", response);
    close(sockfd);
    free(message);
    free(url);
    return response;
}

char *add_movie(char **cookies, int cookies_number, char **jwt, int jwt_number)
{
    int sockfd;
    int year;
    double rating;
    char title[FIELD_SIZE], description[FIELD_SIZE];
    printf("year=\n");
    scanf("%d", &year);
    getchar(); // elibereaza buffer-ul, sciate \n din el

    printf("title=\n");
    fgets(title, FIELD_SIZE, stdin);
    title[strcspn(title, "\n")] = 0;

    printf("description=\n");
    fgets(description, FIELD_SIZE, stdin);
    description[strcspn(description, "\n")] = 0;

    printf("rating=\n");
    scanf("%lf", &rating);
    getchar();

    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);

    json_object_set_string(root_object, "title", title);
    json_object_set_number(root_object, "year", year);
    json_object_set_string(root_object, "description", description);
    json_object_set_number(root_object, "rating", rating);

    // Serializează JSON-ul într-un string
    char *serialized_body = json_serialize_to_string_pretty(root_value);
    char **body_data = malloc(BUFLEN);
    body_data[0] = strdup(serialized_body);

    sockfd = open_connection(SERVERADDR, PORT, AF_INET, SOCK_STREAM, 0);
    char *message = compute_post_request(SVPORT, "/api/v1/tema/library/movies", "application/json",
                                         body_data, 1, cookies, cookies_number, jwt, jwt_number);
    // printf("\nmesajul trimis catre server:\n%s\n", message);
    send_to_server(sockfd, message);

    char *response = strdup(receive_from_server(sockfd));

    // printf("\nraspunsul primit de la server:\n %s\n", response);
    close(sockfd);
    free(message);
    free(body_data[0]);
    free(body_data);
    json_free_serialized_string(serialized_body);
    json_value_free(root_value);
    return response;
}

char *update_movie(char **cookies, int cookies_number, char **jwt, int jwt_number)
{
    int sockfd;
    int id;
    int year;
    double rating;
    char title[FIELD_SIZE], description[FIELD_SIZE];
    printf("id=\n");
    scanf("%d", &id);
    getchar(); // elibereaza buffer-ul, sciate \n din el

    printf("year=\n");
    scanf("%d", &year);
    getchar(); // elibereaza buffer-ul, sciate \n din el

    printf("title=\n");
    fgets(title, FIELD_SIZE, stdin);
    title[strcspn(title, "\n")] = 0;

    printf("description=\n");
    fgets(description, FIELD_SIZE, stdin);
    description[strcspn(description, "\n")] = 0;

    printf("rating=\n");
    scanf("%lf", &rating);
    getchar();

    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);

    json_object_set_string(root_object, "title", title);
    json_object_set_number(root_object, "year", year);
    json_object_set_string(root_object, "description", description);
    json_object_set_number(root_object, "rating", rating);

    // Serializează JSON-ul într-un string
    char *serialized_body = json_serialize_to_string_pretty(root_value);
    char **body_data = malloc(BUFLEN);
    body_data[0] = strdup(serialized_body);

    // Login into server
    sockfd = open_connection(SERVERADDR, PORT, AF_INET, SOCK_STREAM, 0);
    char *url = calloc(FIELD_SIZE, 1);
    sprintf(url, "/api/v1/tema/library/movies/%d", id);
    // printf("\nurl: %s\n", url);
    char *message = compute_put_request(SVPORT, url, "application/json",
                                        body_data, 1, cookies,
                                        cookies_number, jwt, jwt_number);
    // printf("\nmesajul trimis catre server:\n%s\n", message);
    send_to_server(sockfd, message);
    char *response = receive_from_server(sockfd);
    // printf("\nraspunsul de la server:\n%s\n", response);
    close(sockfd);
    free(url);
    free(message);
    return response;
}

char *delete_movie(char **cookies, int cookies_number, char **jwt, int jwt_number)
{
    int sockfd;
    int id = 0;
    printf("id=");
    scanf("%d", &id);
    // Login into server
    sockfd = open_connection(SERVERADDR, PORT, AF_INET, SOCK_STREAM, 0);
    char *url = calloc(FIELD_SIZE, 1);
    sprintf(url, "/api/v1/tema/library/movies/%d", id);
    // printf("\nurl: %s\n", url);
    char *message = compute_delete_request(SVPORT, url, "application/json",
                                           cookies, cookies_number, jwt, jwt_number);
    // printf("\nmesajul trimis catre server:\n%s\n", message);
    send_to_server(sockfd, message);
    char *response = receive_from_server(sockfd);
    // printf("\nraspunsul de la server:\n%s\n", response);
    close(sockfd);
    free(url);
    free(message);
    return response;
}

//____________________________________________COLLECTIONS__________________________________________________

char *get_collections(char **cookies, int cookies_number, char **jwt, int jwt_number)
{
    int sockfd;
    // Login into server
    sockfd = open_connection(SERVERADDR, PORT, AF_INET, SOCK_STREAM, 0);
    char *message = compute_get_request(SVPORT, "/api/v1/tema/library/collections",
                                        NULL, cookies,
                                        cookies_number, jwt, jwt_number);
    // printf("\nmesajul trimis catre server:\n%s\n", message);
    send_to_server(sockfd, message);
    char *response = receive_from_server(sockfd);
    // printf("raspunsul primit de la server: \n%s\n", response);
    close(sockfd);
    free(message);
    return response;
}

char *get_collection(char **cookies, int cookies_number, char **jwt, int jwt_number)
{
    int sockfd;
    int id = 0;
    printf("id=");
    scanf("%d", &id);
    // Login into server
    sockfd = open_connection(SERVERADDR, PORT, AF_INET, SOCK_STREAM, 0);
    char *url = calloc(FIELD_SIZE, 1);
    sprintf(url, "/api/v1/tema/library/collections/%d", id);
    char *message = compute_get_request(SVPORT, url, NULL, cookies,
                                        cookies_number, jwt, jwt_number);
    // printf("\nmesajul trimis catre server:\n%s\n", message);
    send_to_server(sockfd, message);
    char *response = receive_from_server(sockfd);
    // printf("raspunsul primit de la server: \n%s\n", response);
    close(sockfd);
    free(message);
    return response;
}

char *add_collection(char **cookies, int cookies_number, char **jwt, int jwt_number)
{

    int sockfd;
    int num_movies;
    int movie_id;
    char title[FIELD_SIZE];

    printf("title=\n");
    fgets(title, FIELD_SIZE, stdin);
    title[strcspn(title, "\n")] = 0;

    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);

    json_object_set_string(root_object, "title", title);

    // Serializează JSON-ul într-un string
    char *serialized_body = json_serialize_to_string_pretty(root_value);
    char **body_data = malloc(BUFLEN);
    body_data[0] = strdup(serialized_body);

    sockfd = open_connection(SERVERADDR, PORT, AF_INET, SOCK_STREAM, 0);
    char *message = compute_post_request(SVPORT, "/api/v1/tema/library/collections",
                                         "application/json",
                                         body_data, 1, cookies, cookies_number,
                                         jwt, jwt_number);
    // printf("\nmesajul trimis catre server:\n%s\n", message);
    send_to_server(sockfd, message);

    char *response = strdup(receive_from_server(sockfd));

    // printf("\nraspunsul primit de la server:\n %s\n", response);
    printf("num_movies=\n");
    scanf("%d", &num_movies);
    getchar();
    root_value = json_parse_string(extract_json_payload(response));
    root_object = json_value_get_object(root_value);

    int collection_id = (int)json_object_get_number(root_object, "id");

    close(sockfd);
    free(message);
    free(body_data[0]);
    free(body_data);
    json_free_serialized_string(serialized_body);
    json_value_free(root_value);

    // adaugam filmele in colectie
    for (int i = 0; i < num_movies; i++)
    {
        printf("movie_id[%d]=\n", i);
        scanf("%d", &movie_id);
        getchar(); // elibereaza buffer-ul
        //_______TODO_______de adaugat filmele cu id-ul movie_id in colectie
        JSON_Value *root_value_movie = json_value_init_object();
        JSON_Object *root_object_movie = json_value_get_object(root_value_movie);

        json_object_set_number(root_object_movie, "id", movie_id);
        // Serializează JSON-ul într-un string
        char *serialized_body_movie = json_serialize_to_string_pretty(root_value_movie);
        char **body_data = malloc(BUFLEN);
        body_data[0] = strdup(serialized_body_movie);
        char *url = calloc(FIELD_SIZE, 1);
        sprintf(url, "/api/v1/tema/library/collections/%d/movies", collection_id);
        sockfd = open_connection(SERVERADDR, PORT, AF_INET, SOCK_STREAM, 0);
        char *message = compute_post_request(SVPORT, url, "application/json",
                                             body_data, 1, cookies, cookies_number,
                                             jwt, jwt_number);
        // printf("\nmesajul trimis catre server:\n%s\n", message);
        send_to_server(sockfd, message);

        char *response = strdup(receive_from_server(sockfd));

        // printf("\nraspunsul primit de la server:\n %s\n", response);

        if (strstr(extract_sv_resp_status(response), "message") != NULL)
        {
            printf("SUCCESS: Movie added to collection successfully\n");
        }
        else
        {
            printf("ERROR: A aparut o eroare la adaugarea filmelor in colectie\n");
            return response;
        }
        close(sockfd);
        free(message);
        free(body_data[0]);
        free(body_data);
        json_free_serialized_string(serialized_body_movie);
        json_value_free(root_value_movie);
    }

    return response;
}

char *delete_collection(char **cookies, int cookies_number, char **jwt, int jwt_number)
{
    int sockfd;
    int id = 0;
    printf("id=");
    scanf("%d", &id);
    // Login into server
    sockfd = open_connection(SERVERADDR, PORT, AF_INET, SOCK_STREAM, 0);
    char *url = calloc(FIELD_SIZE, 1);
    sprintf(url, "/api/v1/tema/library/collections/%d", id);
    // printf("\nurl: %s\n", url);
    char *message = compute_delete_request(SVPORT, url, "application/json",
                                           cookies, cookies_number, jwt, jwt_number);
    // printf("\nmesajul trimis catre server:\n%s\n", message);
    send_to_server(sockfd, message);
    char *response = receive_from_server(sockfd);
    // printf("\nraspunsul de la server:\n%s\n", response);
    close(sockfd);
    free(url);
    free(message);
    return response;
}

char *add_movie_to_collection(char **cookies, int cookies_number, char **jwt, int jwt_number)
{

    int sockfd;
    int collection_id;
    int movie_id;

    printf("collection_id=\n");
    scanf("%d", &collection_id);
    getchar();

    printf("movie_id=\n");
    scanf("%d", &movie_id);
    getchar();

    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);

    json_object_set_number(root_object, "id", movie_id);
    // Serializează JSON-ul într-un string
    char *serialized_body = json_serialize_to_string_pretty(root_value);
    char **body_data = malloc(BUFLEN);
    body_data[0] = strdup(serialized_body);
    char *url = calloc(FIELD_SIZE, 1);
    sprintf(url, "/api/v1/tema/library/collections/%d/movies", collection_id);
    sockfd = open_connection(SERVERADDR, PORT, AF_INET, SOCK_STREAM, 0);
    char *message = compute_post_request(SVPORT, url, "application/json",
                                         body_data, 1, cookies, cookies_number,
                                         jwt, jwt_number);
    // printf("\nmesajul trimis catre server:\n%s\n", message);
    send_to_server(sockfd, message);

    char *response = strdup(receive_from_server(sockfd));

    // printf("\nraspunsul primit de la server:\n %s\n", response);

    close(sockfd);
    free(message);
    free(body_data[0]);
    free(body_data);
    json_free_serialized_string(serialized_body);
    json_value_free(root_value);
    return response;
}

char *delete_movie_from_collection(char **cookies, int cookies_number, char **jwt,
                                   int jwt_number)
{
    int sockfd;
    int collection_id;
    int movie_id;

    printf("collection_id=\n");
    scanf("%d", &collection_id);
    getchar();

    printf("movie_id=\n");
    scanf("%d", &movie_id);
    getchar();
    // Login into server
    sockfd = open_connection(SERVERADDR, PORT, AF_INET, SOCK_STREAM, 0);
    char *url = calloc(FIELD_SIZE, 1);
    sprintf(url, "/api/v1/tema/library/collections/%d/movies/%d", collection_id, movie_id);
    // printf("\nurl: %s\n", url);
    char *message = compute_delete_request(SVPORT, url, "application/json",
                                           cookies, cookies_number, jwt, jwt_number);
    // printf("\nmesajul trimis catre server:\n%s\n", message);
    send_to_server(sockfd, message);
    char *response = receive_from_server(sockfd);
    // printf("\nraspunsul de la server:\n%s\n", response);
    close(sockfd);
    free(url);
    free(message);
    return response;
}