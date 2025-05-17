#define LOGIN_ADMIN 1
#define ADD_USER 2
#define GET_USERS 3
#define DELETE_USER 4
#define LOGOUT_ADMIN 5
#define LOGIN 6
#define GET_ACCESS 7
#define GET_MOVIES 8
#define GET_MOVIE 9
#define ADD_MOVIE 10
#define DELETE_MOVIE 11
#define UPDATE_MOVIE 12
#define GET_COLLECTIONS 13
#define GET_COLLECTION 14
#define ADD_COLLECTION 15
#define DELETE_COLLECTION 16
#define ADD_MOVIE_TO_COLLECTION 17
#define DELETE_MOVIE_FROM_COLLECTION 18
#define LOGOUT 19
#define EXIT 20
#define UNKNOWN 21

/// @brief functie care returneaza cookie-ul din raspunsul primit de la server
/// @param response
/// @return
void print_movie_details(char *response);
void print_collection(char *response);
void print_collections(char *response);
void print_movies_array(char *json_string);
char *extract_json_payload(const char *response);
char *extract_cookie(char *response);
char *login_admin();
char *add_user(char **cookies, int cookies_number);
char *get_users(char **cookies, int cookies_number);
char *delete_user(char **cookies, int cookies_number);
char *logout_admin(char **cookies, int cookies_number);
char *login();
char *add_movie(char **cookies, int cookies_number, char **jwt, int jwt_number);
const char *extract_sv_resp_status(char *response);
char *logout(char **cookies, int cookies_number);
char *get_access(char **cookies, int cookies_number);
const char *extract_JWT(char *response);
char *get_movies(char **cookies, int cookies_number, char **jwt, int jwt_number);
char *get_movie(char **cookies, int cookies_number, char **jwt, int jwt_number);
char *update_movie(char **cookies, int cookies_number, char **jwt, int jwt_number);
char *delete_movie(char **cookies, int cookies_number, char **jwt, int jwt_number);
char *get_collections(char **cookies, int cookies_number, char **jwt, int jwt_number);
char *get_collection(char **cookies, int cookies_number, char **jwt, int jwt_number);
char *add_collection(char **cookies, int cookies_number, char **jwt, int jwt_number);
char *delete_collection(char **cookies, int cookies_number, char **jwt, int jwt_number);
char *add_movie_to_collection(char **cookies, int cookies_number, char **jwt, int jwt_number);
char *delete_movie_from_collection(char **cookies, int cookies_number, char **jwt, int jwt_number);
