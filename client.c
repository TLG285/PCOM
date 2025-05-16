#include <stdio.h>      /* printf, sprintf */
#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include "helpers.h"
#include "requests.h"
#include "myfunctions.h"
#include "buffer.h"
#include "parson.h"

int parse_command(const char *input)
{
    if (strcmp(input, "login_admin") == 0)
        return LOGIN_ADMIN;
    if (strcmp(input, "add_user") == 0)
        return ADD_USER;
    if (strcmp(input, "get_users") == 0)
        return GET_USERS;
    if (strcmp(input, "delete_user") == 0)
        return DELETE_USER;
    if (strcmp(input, "logout_admin") == 0)
        return LOGOUT_ADMIN;
    if (strcmp(input, "login") == 0)
        return LOGIN;
    if (strcmp(input, "get_access") == 0)
        return GET_ACCESS;
    if (strcmp(input, "get_movies") == 0)
        return GET_MOVIES;
    if (strcmp(input, "get_movie") == 0)
        return GET_MOVIE;
    if (strcmp(input, "add_movie") == 0)
        return ADD_MOVIE;
    if (strcmp(input, "delete_movie") == 0)
        return DELETE_MOVIE;
    if (strcmp(input, "update_movie") == 0)
        return UPDATE_MOVIE;
    if (strcmp(input, "get_collections") == 0)
        return GET_COLLECTIONS;
    if (strcmp(input, "get_collection") == 0)
        return GET_COLLECTION;
    if (strcmp(input, "add_collection") == 0)
        return ADD_COLLECTION;
    if (strcmp(input, "delete_collection") == 0)
        return DELETE_COLLECTION;
    if (strcmp(input, "add_movie_to_collection") == 0)
        return ADD_MOVIE_TO_COLLECTION;
    if (strcmp(input, "delete_movie_from_collection") == 0)
        return DELETE_MOVIE_FROM_COLLECTION;
    if (strcmp(input, "logout") == 0)
        return LOGOUT;
    if (strcmp(input, "exit") == 0)
        return EXIT;
    return UNKNOWN;
}

void run_client()
{
    char command[64];
    char *cookies[80];
    char *JWT[80];
    int current_cookie = 0;
    int current_jwt = 0;
    while (1)
    {
        if (fgets(command, sizeof(command), stdin) == NULL)
            break;

        // Elimină newline de la sfârșit dacă există
        size_t len = strlen(command);
        if (len > 0 && command[len - 1] == '\n')
        {
            command[len - 1] = '\0';
        }

        switch (parse_command(command))
        {
        case LOGIN_ADMIN:
            char *response = login_admin();
            cookies[current_cookie] = extract_cookie(response);
            // printf("cookie: %s", extract_cookie(response));
            current_cookie++;
            JSON_Value *root_val = json_parse_string(extract_json_payload(response));
            char *status = extract_sv_resp_status(response);
            if (strstr(status, "error") != NULL)
            {
                printf("ERROR: Credidentiale gresite pentru admin\n");
            }
            else if (strstr(status, "message") != NULL)
            {
                printf("SUCCESS: Adminul s-a logat cu success\n");
            }
            else
            {
                printf("Problema cu serverul");
            }
            break;
        case ADD_USER:
            response = add_user(cookies, current_cookie);
            root_val = json_parse_string(extract_json_payload(response));
            status = extract_sv_resp_status(response);
            if (strstr(status, "error") != NULL)
            {
                printf("ERROR: Userul nu a putut fi adaugat\n");
            }
            else if (strstr(status, "message") != NULL)
            {
                printf("SUCCESS: Userul a fost adaugat\n");
            }
            else
            {
                printf("Problema cu serverul");
            }
            break;
        case GET_USERS:
            get_users(cookies, current_cookie);
            break;
        case DELETE_USER:
            response = delete_user(cookies, current_cookie);
            if (strstr(extract_json_payload(response), "error") != NULL)
            {
                printf("ERROR: A aparut o eroare la stergere/Admin privileges required\n");
            }
            else if (strstr(status, "message") != NULL)
            {
                printf("SUCCESS: Userul a fost sters\n");
            }
            else
            {
                printf("Problema cu serverul");
            }
            break;
        case LOGOUT_ADMIN:
            response = logout_admin(cookies, current_cookie);
            cookies[current_cookie] = NULL;
            current_cookie = 0;
            JWT[current_jwt] = NULL;
            current_jwt = 0;
            status = extract_sv_resp_status(response);
            if (strstr(status, "error") != NULL)
            {
                printf("ERROR: Nu am putut deloga adminul\n");
            }
            else if (strstr(status, "message") != NULL)
            {
                printf("SUCCESS: Adminul s-a delogat cu success\n");
            }
            else
            {
                printf("Problema cu serverul");
            }
            break;
        case LOGIN:
            response = login(cookies, current_cookie);
            cookies[current_cookie] = extract_cookie(response);
            // printf("cookie: %s", extract_cookie(response));
            current_cookie++;
            status = extract_sv_resp_status(response);
            if (strstr(status, "error") != NULL)
            {
                printf("ERROR: Credidentiale gresite pentru utilizator\n");
            }
            else if (strstr(status, "message") != NULL)
            {
                printf("SUCCESS: Userul s-a logat cu success\n");
            }
            else
            {
                printf("Problema cu serverul");
            }
            break;
        case GET_ACCESS:
            if (current_cookie == 0)
            {
                printf("ERROR: Trebuie sa fi autentificat mai intai\n");
            }
            else
            {
                response = get_access(cookies, current_cookie);
                status = extract_sv_resp_status(response);
                char *jwt = extract_JWT(response);
                JWT[current_jwt] = jwt;
                current_jwt += 1;
                if (strstr(status, "error") != NULL)
                {
                    printf("ERROR: s-a primit eroare la JWT token\n");
                }
                else if (strstr(status, "token") != NULL)
                {
                    printf("SUCCESS: Token JWT primit\n");
                }
                else
                {
                    printf("Problema cu serverul");
                }
            }
            break;
        case GET_MOVIES:
            response = get_movies(cookies, current_cookie, JWT, current_jwt);
            print_movies_array(response);
            break;
        case GET_MOVIE:
            response = get_movie(cookies, current_cookie, JWT, current_jwt);
            status = extract_sv_resp_status(response);
            if (strstr(status, "description") != NULL)
            {
                print_movie_details(response);
            }
            else
            {
                printf("ERROR: a aparut o eroare la afisarea detaliilor despre film\n");
            }
            // // TO DOO: de rezolvat problema cu afisarea, nu afiseaza ce trebuie
            break;
        case ADD_MOVIE:
            response = add_movie(cookies, current_cookie, JWT, current_jwt);
            if (strstr(response, "CREATED") != NULL)
            {
                printf("SUCCESS: Am adaugat filmul\n");
            }
            else
            {
                printf("ERROR: A aparut o eroare la adaugarea filmului\n");
            }
            break;
        case DELETE_MOVIE:
            response = delete_movie(cookies, current_cookie, JWT, current_jwt);
            status = extract_sv_resp_status(response);
            if (strstr(status, "message") != NULL)
            {
                printf("SUCCESS: Filmul a fost sters\n");
            }
            else
            {
                printf("ERROR: A aparut o eroare la stergerea filmului\n");
            }
            break;
        case UPDATE_MOVIE:
            response = update_movie(cookies, current_cookie, JWT, current_jwt);
            if (strstr(response, "OK") != NULL)
            {
                printf("SUCCESS: Userul a fost updatat cu success\n");
            }
            else
            {
                printf("ERROR: A aparut o eroare la updateul filmului\n");
            }
            break;
        case GET_COLLECTIONS:
            response = get_collections(cookies, current_cookie, JWT, current_jwt);
            if (strstr(extract_sv_resp_status(response), "collections"))
            {
                printf("SUCCESS: Lista colectiilor\n");
                // TODO: de adaugat afisarea colectiilor
                print_collections(response);
            }
            else
            {
                printf("ERROR: A aparut o eroare la afisarea colectiilor\n");
            }
            break;
        case GET_COLLECTION:
            response = get_collection(cookies, current_cookie, JWT, current_jwt);
            status = extract_sv_resp_status(response);
            if (strstr(status, "id") != NULL)
            {
                printf("SUCCESS: Detalii colecție\n");
                // TODO: de adaugat afisarea colectiei
                print_collection(response);
            }
            else
            {
                printf("ERROR: A aparut o eroare la afisarea colectiei\n");
            }
            break;
        case ADD_COLLECTION:
            printf("Comanda: add_collection\n");
            response = add_collection(cookies, current_cookie, JWT, current_jwt);

            break;
        case DELETE_COLLECTION:
            printf("Comanda: delete_collection\n");
            delete_collection(cookies, current_cookie, JWT, current_jwt);
            status = extract_sv_resp_status(response);
            if (strstr(extract_sv_resp_status(response), "id") != NULL)
            {
                printf("SUCCESS: Colectia a fost stearsa\n");
            }
            else
            {
                printf("ERROR: A aparut o eroare la stergerea colectiei\n");
            }
            break;
        case ADD_MOVIE_TO_COLLECTION:
            response = add_movie_to_collection(cookies, current_cookie, JWT, current_jwt);
            status = extract_sv_resp_status(response);
            if (strstr(extract_sv_resp_status(response), "message") != NULL)
            {
                printf("SUCCESS: Filmul a fost adaugat la colectie\n");
            }
            else
            {
                printf("ERROR: A aparut o eroare la adaugarea filmului in colectiei\n");
            }
            break;
        case DELETE_MOVIE_FROM_COLLECTION:
            printf("Comanda: delete_movie_from_collection\n");
            response = delete_movie_from_collection(cookies, current_cookie, JWT, current_jwt);
            if (strstr(extract_sv_resp_status(response), "message") != NULL)
            {
                printf("SUCCESS: Filmul a fost sters din colectie\n");
            }
            else
            {
                printf("ERROR: A aparut o eroare la stergerea filmului din colectiei\n");
            }
            break;
        case LOGOUT:
            // aici s-ar putea sa fie o problema la strstr, nu sunt inca sigur
            response = logout(cookies, current_cookie);
            cookies[current_cookie] = NULL;
            current_cookie = 0;
            JWT[current_jwt] = NULL;
            current_jwt = 0;
            status = extract_sv_resp_status(response);
            if (strstr(status, "error") != NULL)
            {
                printf("ERROR: Nu am putut deloga userul\n");
            }
            else if (strstr(status, "message") != NULL)
            {
                printf("SUCCESS: Userul s-a delogat cu success\n");
            }
            else
            {
                printf("Problema cu serverul");
            }
            break;
        case EXIT:
            return 0;
        case UNKNOWN:
        default:
            break;
        }
    }
}

int main(int argc, char *argv[])
{
    run_client();
    return 0;
}
