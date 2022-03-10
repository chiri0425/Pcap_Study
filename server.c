#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>

#define BUF_SIZE 100
#define MAX_CLNT 256
#define USER_ID_SIZE 21
#define MAX_ROOM 2
#define ROOM_NAME_SIZE 21
#define ANSWER_SIZE 3

typedef struct User {
	char id[USER_ID_SIZE];
	int sock;
} User;

typedef struct UserController {
	User* user_list[MAX_CLNT];
	int cnt;
} UserController;

typedef struct GameController {
	char answer_list[2][5];
	int ready_state[2];
	int turn;
} GameController;

typedef struct Stat {
	char id[USER_ID_SIZE];
	int win, draw, lose;
} Stat;

typedef struct Room {
	int id;
	char user_id[2][USER_ID_SIZE];
	char name[ROOM_NAME_SIZE];
	int clnt_sock[2];
	int cnt;
	GameController gameController;
} Room;

typedef struct MatchingRoomController {
	Room* room_list[MAX_ROOM];
	int cnt; // matching room count
} MatchingRoomController;

typedef struct CreatedRoomController {
	Room* room_list[30];
	int cnt;   // created room count
} CreatedRoomController;

void error_handling(char* msg);

// client handling thread
void* handle_clnt(void* arg);
// client enter this room and play game
void create_matching_rooms();
// needed for login_view
User* login_view(void* arg);
int login(void* arg, User* user);
int sign_up(void* arg);
int rw_login_db(char* mode, char* id, char* pw);
// needed for main_view
int main_view(User* user);
Room* get_matching_room(User* user);
Room* get_create_room(User* user);
int room_view(User* user, Room* room);
int start_game(User* user, Room* room);
int waiting_user_ready(User* user, Room* room);
int enter_created_room(User* user);
//void send_msg(User* user, char* msg, int len, int num);
void search_room(User* user);
void search_user(User* user);
void print_ranking(User* user);
int input_rank(char id[USER_ID_SIZE], int outcome);

// removing socket from socket array
void delete_room(Room* room);
void* write_log();
//char* itoa(long val, char* buf, unsigned radix);

UserController userController;
MatchingRoomController mRoomController;
CreatedRoomController cRoomController;
pthread_mutex_t sock_mutx;
pthread_mutex_t login_db_mutx;
pthread_mutex_t room_mutx;
pthread_mutex_t matching_mutx;
int log_fds[2];
char log_msg[100];

int main(int argc, char* argv[])
{
	int serv_sock, clnt_sock;
	struct sockaddr_in serv_adr, clnt_adr;
	int clnt_adr_sz;
	cRoomController.cnt = 0;
	pthread_t t_id;

	if (argc != 2) {
		printf("Usage: %s <port>\n", argv[0]);
		exit(1);
	}

	serv_sock = socket(PF_INET, SOCK_STREAM, 0);

	memset(&serv_adr, 0, sizeof(serv_adr));
	serv_adr.sin_family = AF_INET;
	serv_adr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_adr.sin_port = htons(atoi(argv[1]));

	if (bind(serv_sock, (struct sockaddr*) & serv_adr, sizeof(serv_adr)) == -1)
		error_handling("bind() error");
	if (listen(serv_sock, 10) == -1)
		error_handling("listen() error");

	userController.cnt = 0; // userController init
	create_matching_rooms();   // matching room init
	pipe(log_fds);      
	pthread_create(&t_id, NULL, write_log, NULL);   // writing log init
	pthread_detach(t_id);

	while (1) {
		clnt_adr_sz = sizeof(clnt_adr);
		clnt_sock = accept(serv_sock, (struct sockaddr*) & clnt_adr, &clnt_adr_sz);

		pthread_create(&t_id, NULL, handle_clnt, (void*)& clnt_sock);
		pthread_detach(t_id);
		printf("Connected client IP : %s \n", inet_ntoa(clnt_adr.sin_addr));
		sprintf(log_msg, "Connected client IP: %s \n", inet_ntoa(clnt_adr.sin_addr));
		write(log_fds[1], log_msg, strlen(log_msg));
		//handle_clnt(&clnt_sock);
	}
	close(serv_sock);
	return 0;
}

void create_matching_rooms() {
	char name[USER_ID_SIZE] = "matching_room";
	mRoomController.cnt = 0;   // mRoom cnt init;

	for (int i = 0; i < 2; i++) {
		Room* room = (Room*)malloc(sizeof(Room));
		room->id = i + 1;
		strcpy(room->name, name);
		room->name[strlen(name)] = (i + 1) + '0';   // int to char / "matching_room1",...
		room->cnt = 0;

		// room->gameControl init
		memset(&(room->gameController), 0, sizeof(room->gameController));

		// add room at room_list in roomController
		mRoomController.room_list[mRoomController.cnt++] = room;
	}
	sprintf(log_msg, "Start matiching system\n");
	write(log_fds[1], log_msg, strlen(log_msg));
	return;

}

void* write_log() {    
	int len;
	FILE* fp = NULL;
	while (1) {
		char buf[100] = { 0, };
		len = read(log_fds[0], buf, sizeof(buf));
		if ((fp = fopen("log.txt", "a")) != NULL) {
			fprintf(fp, "%s", buf);
			fclose(fp);
		}
		else {
			printf("fail open file\n");
		};
	}
	return NULL;
}


void error_handling(char* msg) {
	fputs(msg, stderr);
	fputc('\n', stderr);
	exit(1);
}

void* handle_clnt(void* arg) {
	int clnt_sock = *((int*)arg);
	int room_num = 0;
	int view_mode = 1;
	int i;
	User* user;

	if ((user = login_view(&clnt_sock)) != NULL) {
		pthread_mutex_lock(&sock_mutx);   // sock mutex lock
		userController.user_list[userController.cnt++] = user;
		pthread_mutex_unlock(&sock_mutx);   // sock mutex unlock


		main_view(user);
	}
	if (user == NULL) {
		printf("End of connection on the login screen\n");
		sprintf(log_msg, "End of connection on the login screen\n");
		write(log_fds[1], log_msg, strlen(log_msg));
	}
	else {
		printf("%s : End of connection\n", user->id);
		sprintf(log_msg, "%s : End of connection\n", user->id);
		write(log_fds[1], log_msg, strlen(log_msg));

		pthread_mutex_lock(&sock_mutx);   // sock mutex lock
		if (userController.cnt == 1) {
			userController.user_list[0] = NULL;
		}
		else {
			for (i = 0; i < userController.cnt; i++) {
				if (strcmp(user->id, userController.user_list[i]->id) == 0) {

					for (; i < userController.cnt; i++) {
						userController.user_list[i] = userController.user_list[i + 1];
					}
					userController.user_list[userController.cnt] = NULL;
					break;
				}
			}
		}
		userController.cnt--;
		pthread_mutex_unlock(&sock_mutx);   // sock mutex unlock
		free(user);
	}
	close(clnt_sock);

	return NULL;
}

User* login_view(void* arg) {
	int clnt_sock = *((int*)arg);
	User* user = (User*)malloc(sizeof(User));
	char msg[BUF_SIZE];
	char answer[ANSWER_SIZE];
	int login_result = 0;
	int str_len = 0;

	memset(user, 0, sizeof(user));   // user init

	while (1) {
		str_len = read(clnt_sock, answer, sizeof(answer));
		if (str_len == -1) // read() error
			return 0;
		answer[str_len - 1] = '\0';

		switch (answer[0]) {
		case '1':
			login_result = login(&clnt_sock, user);

			if (login_result == 1)
				return user;   
			else
				break;
		case '2':
			sign_up(&clnt_sock);
			break;
		case '3':
			printf("client close\n");
			return NULL;
		default:
			break;
		}
	}

	return NULL;
}

int login(void* arg, User* user) {
	int clnt_sock = *((int*)arg);
	char mode[5] = "r";
	char uid[USER_ID_SIZE] = { 0 };
	char upw[USER_ID_SIZE] = { 0 };
	char answer[ANSWER_SIZE] = "0\n";
	char msg[BUF_SIZE] = { 0 };
	char* str = NULL;
	int verify_result = 0;
	int str_len = 0;
	int i;
	
	str_len = read(clnt_sock, msg, sizeof(msg));
	if (str_len == -1) // read() error
		return 0;
	printf("%s\n", msg);

	str = strtok(msg, "\n");   
	strncpy(uid, str, strlen(str));
	fprintf(stdout, "uid: %s\n", uid);

	printf("remain msg: %s\n", msg);
	str = strtok(NULL, "\n");   
	strncpy(upw, str, strlen(str));
	fprintf(stdout, "upw: %s\n", upw); 

	if ((verify_result = rw_login_db(mode, uid, upw)) == 1) {
		for (i = 0; i < userController.cnt; i++) {
			if (strcmp(userController.user_list[i]->id, uid) == 0) {
				printf("Already exit!\n");
				write(clnt_sock, "2\n", sizeof("2\n"));
				return 2;
			}
		}
		answer[0] = '1';
		strncpy(user->id, uid, strlen(uid));  
		user->sock = clnt_sock;   

		printf("%s : login success\n", user->id);
		sprintf(log_msg, "%s : login success\n", user->id);
		write(log_fds[1], log_msg, strlen(log_msg));
	}

	str_len = write(clnt_sock, answer, strlen(answer));
	if (str_len == -1) // write() error
		return 0;

	return verify_result;
}

int sign_up(void* arg) {
	int clnt_sock = *((int*)arg);
	char mode[3] = "r+";   // needed for login_db fopen
	char uid[USER_ID_SIZE] = { 0, };
	char upw[USER_ID_SIZE] = { 0, };
	int sign_up_result = 0;
	char answer[ANSWER_SIZE] = { 0, };
	char msg[BUF_SIZE] = { 0, };
	char* str;
	int str_len = 0;

	//str_len = read(clnt_sock, answer, sizeof(answer));
	//if (str_len == -1) // read() error
	   //return 0;
	//printf("str_:%d, str:%ld, %s\n", str_len, strlen(answer), answer);

	//if (!(strcmp(answer, "y\n")) || !(strcmp(answer, "Y\n"))) {
	str_len = read(clnt_sock, msg, sizeof(msg));
	if (str_len == -1) // read() error
		return 0;
	//printf("str_:%d, str:%ld\n", str_len, strlen(upw));

	str = strtok(msg, "\n");   
	strncpy(uid, str, strlen(str));
	fprintf(stdout, "uid: %s\n", uid);
	str = strtok(NULL, "\n");   
	strncpy(upw, str, strlen(str));
	fputs(upw, stdout);

	
	sign_up_result = rw_login_db(mode, uid, upw);

	if (sign_up_result == 1) {
		answer[0] = '1';
		printf("create account: %s\n", uid);
		sprintf(log_msg, "create account success: %s\n", uid);
		write(log_fds[1], log_msg, strlen(log_msg));
	}
	else {
		answer[0] = '0';
		printf("create account fail\n");
		sprintf(log_msg, "create account fail\n");
		write(log_fds[1], log_msg, strlen(log_msg));
	}

	str_len = write(clnt_sock, answer, strlen(answer));
	if (str_len == -1) // write() error
		return 0;

	return sign_up_result;
}


int main_view(User* user) {
	int clnt_sock = user->sock;
	char answer[ANSWER_SIZE] = { 0, };
	Room* room;
	int str_len = 0;

	printf("%s : Enter the lobby\n", user->id);
	sprintf(log_msg, "%s : Enter the lobby\n", user->id);
	write(log_fds[1], log_msg, strlen(log_msg));

	while (1) {
		str_len = read(clnt_sock, answer, sizeof(answer));
		if (str_len == -1) // read() error
			return 0;
		answer[str_len - 1] = '\0';

		switch (answer[0]) {
		case '1':     
			if ((room = get_matching_room(user)) != NULL) {
				room_view(user, room);
			}
			break;

		case '2':
			printf("%s logout\n", user->id);
			return 0;
		default:
			break;
		}
	}

	return 0;
}

Room* get_matching_room(User* user) {
	int clnt_sock = user->sock;
	Room* room;
	int entered = 0;
	int in_room_cnt = 0;

	printf("%s : Matching request\n", user->id);
	sprintf(log_msg, "%s : Matching request\n", user->id);
	write(log_fds[1], log_msg, strlen(log_msg));

	// mutex lock
	pthread_mutex_lock(&matching_mutx);
	for (int i = 0; i < mRoomController.cnt; i++) {
		in_room_cnt = mRoomController.room_list[i]->cnt;
		if (in_room_cnt < 2) {   // empty space in room
			room = mRoomController.room_list[i];
			room->clnt_sock[in_room_cnt] = user->sock;
			memcpy(room->user_id[in_room_cnt], user->id, sizeof(user->id));
			room->cnt++;
			entered = 1;
			printf(" in the user room %dromm %duser\n", i, room->cnt);
			break;
		}
	}
	pthread_mutex_unlock(&matching_mutx);
	// mutex unlock
	if (entered == 1) {
		printf("%s : matching success\n", user->id);
		sprintf(log_msg, "%s : matching suceess\n", user->id);
		write(log_fds[1], log_msg, strlen(log_msg));
		return room;
	}

	return NULL;
}


int room_view(User* user, Room* room) {
	int buf = 0;
	printf("enter Room\n");
	printf("%d\n", room->cnt);

	while (1) {
		buf = (waiting_user_ready(user, room));
		if (buf == 1) {
			start_game(user, room);
		}
		else if (buf == 2) {
			while (room->gameController.ready_state[0] == 1) {
				sleep(1);
			}
		}
		else
			break;
	}

	return 0;
}

int waiting_user_ready(User* user, Room* room) {
	int clnt_sock = user->sock;
	char msg[BUF_SIZE];
	int str_len = 0;
	char* str;
	char start_msg[] = "game ready: /r\t Leaving the room: /q\t help: /?\n";

	write(user->sock, start_msg, sizeof(start_msg));

	while (1) {
		str_len = read(clnt_sock, msg, sizeof(msg));
		if (str_len == -1) // read() error
			return 0;
		msg[str_len] = '\0';
		printf("msg : %s", msg);
		// message control
		if (msg[0] == '/') {
			if (strncmp(msg, "/q\n", strlen("/q\n")) == 0 || strncmp(msg, "/Q\n", strlen("/Q\n")) == 0) {
				if (room->clnt_sock[0] == clnt_sock) {
					write(room->clnt_sock[1], "The other person left the room.\n", sizeof("The other person left the room.\n"));
					room->clnt_sock[0] = room->clnt_sock[1];
				}
				else {
					write(room->clnt_sock[0], "The other person left the room.\n", sizeof("The other person left the room.\n"));
				}
				room->clnt_sock[1] = -1;
				room->cnt--;
				str_len = write(clnt_sock, "/q\n", strlen("/q\n"));
				printf("left the room request\n");
				return 0;
			}
			else if (strcmp(msg, "/?\n") == 0) {
				write(user->sock, start_msg, sizeof(start_msg));      
			}
			else if (strncmp(msg, "/r\n", strlen("r\n")) == 0 || strncmp(msg, "/R\n", strlen("/R\n")) == 0) {
				if (clnt_sock == room->clnt_sock[0]) {
					room->gameController.ready_state[0] = 1;
					if (room->gameController.ready_state[1] != 1) {
						write(room->clnt_sock[1], "The other person ready\n", strlen("The other person ready\n"));
					}
					while (room->gameController.ready_state[1] != 1) {
						sleep(1);
					}
					return 2;
				}
				else {
					room->gameController.ready_state[1] = 1;
					if (room->gameController.ready_state[0] != 1) {
						write(room->clnt_sock[0], "The other person ready\n", strlen("The other person ready\n"));
					}
					while (room->gameController.ready_state[0] != 1) {
						sleep(1);
					}
				}

				if (room->gameController.ready_state[0] && room->gameController.ready_state[1]) {
					write(room->clnt_sock[0], "/r\n", strlen("/r\n"));
					write(room->clnt_sock[1], "/r\n", strlen("/r\n"));
					printf("%s game start -> room:%d %s\n", user->id, room->id, room->name);
					sprintf(log_msg, "game start -> room:%d %s\n", room->id, room->name);
					write(log_fds[1], log_msg, strlen(log_msg));
					return 1;
				}
			}

			continue;
		}

		if (room->cnt == 2) {   
			if (clnt_sock == room->clnt_sock[0] && room->gameController.ready_state[1] != 1) {
				str_len = write(room->clnt_sock[1], msg, str_len);
				if (str_len == -1) // write() error
					return 0;
			}
			else if (clnt_sock == room->clnt_sock[1] && room->gameController.ready_state[0] != 1) {
				str_len = write(room->clnt_sock[0], msg, str_len);
				if (str_len == -1) // write() error
					return 0;
			}
		}
	}

	return 0;
}

int start_game(User* user, Room* room) {
	int str_len = 0;
	char user_num[5] = { 0 };
	char msg[BUF_SIZE] = { 0 };
	char remain_msg[BUF_SIZE * 2] = { 0 };
	int ball = 0, strike = 0;
	int user1_win = 0, user2_win = 0;
	int cnt = 1;
	char result[BUF_SIZE] = { 0 };

	room->gameController.turn = 0;

	str_len = read(room->clnt_sock[0], user_num, sizeof(user_num));
	strncpy(room->gameController.answer_list[0], user_num, sizeof(room->gameController.answer_list[0]));
	printf("user1_num: %s\n", room->gameController.answer_list[0]);

	str_len = read(room->clnt_sock[1], user_num, sizeof(user_num));
	strncpy(room->gameController.answer_list[1], user_num, sizeof(room->gameController.answer_list[1]));
	printf("user2_num: %s\n", room->gameController.answer_list[1]);



	while (1) {
		if (room->gameController.turn == 0) {
			printf("turn1\n");
			str_len = write(room->clnt_sock[0], "/turn1\n", strlen("/turn1\n"));
		}
		else {
			printf("turn2\n");
			str_len = write(room->clnt_sock[1], "/turn2\n", strlen("/turn2\n"));
		}

		str_len = read(room->clnt_sock[room->gameController.turn], user_num, sizeof(user_num));
		user_num[str_len] = '\0';
		if (str_len == 0)   // read() error
			return 0;
		printf("attack num: %s", user_num);

		ball = 0; strike = 0;   // ball strike init

		for (int i = 0; i < 3; i++) {
			for (int j = 0; j < 3; j++) {
				if (user_num[i] == room->gameController.answer_list[!room->gameController.turn][j]) {
					if (i == j)
						strike++;
					else
						ball++;
				}
			}
		}
		printf("result: %dS %dB\n", strike, ball);
		sprintf(result, "[result] %dS %dB\n", strike, ball);

		if (room->gameController.turn == 0) {
			if (strike == 3) {
				user1_win = 1;
				
				sprintf(msg, "%sThat's correct\n If the other person doesn't get it, you win.\n", result);
				write(room->clnt_sock[0], msg, strlen(msg));
			}
			else {
				write(room->clnt_sock[0], result, strlen(result));
			}

			sprintf(remain_msg, "\ndefend %d\nThe number you defended:%s%s", cnt, user_num, result);
			if (user1_win)
				sprintf(remain_msg, "%sThe other person correct the answer\n", remain_msg);
			write(room->clnt_sock[1], remain_msg, strlen(remain_msg));
			str_len = read(room->clnt_sock[1], remain_msg, sizeof(2));

		}
		else if (room->gameController.turn == 1) {
			if (strike == 3) {
				user2_win = 1;
				sprintf(msg, "%scorrect answer\n", result);
				write(room->clnt_sock[1], msg, strlen(msg));
			}
			else {
				write(room->clnt_sock[1], result, strlen(result));
			}

			sprintf(remain_msg, "\ndefend %d\nThe number you defended:%s%s", cnt++, user_num, result);
			if (user2_win)
				sprintf(remain_msg, "%sThe other person correct the answer\n", remain_msg);
			write(room->clnt_sock[0], remain_msg, strlen(remain_msg));
			str_len = read(room->clnt_sock[0], remain_msg, sizeof(2));
			if (user1_win == 1 || user2_win == 1)
				break;
		}

		room->gameController.turn = !room->gameController.turn;
	}

	printf("game over. -> room:%d %s", room->id, room->name);
	sprintf(log_msg, "game over -> room:%d %s", room->id, room->name);
	write(log_fds[1], log_msg, strlen(log_msg));

	if (user2_win) {
		if (user1_win) {
			write(room->clnt_sock[0], "/draw\n", strlen("/draw\n"));
			write(room->clnt_sock[1], "/draw\n", strlen("/draw\n"));
			printf("%s %sdrawn", room->user_id[0], room->user_id[1]);
			sprintf(log_msg, "%s %sdraw\n", room->user_id[0], room->user_id[1]);
			write(log_fds[1], log_msg, strlen(log_msg));
			//input_rank(room->user_id[0], 2);
			//input_rank(room->user_id[1], 2);
		}
		else {
			write(room->clnt_sock[1], "/win\n", strlen("/win\n"));
			write(room->clnt_sock[0], "/lose\n", strlen("/lose\n"));
			printf("%s win %s lose\n", room->user_id[1], room->user_id[0]);
			sprintf(log_msg, "%s win %s lose\n", room->user_id[1], room->user_id[0]);
			write(log_fds[1], log_msg, strlen(log_msg));
			//input_rank(room->user_id[1], 1);
			//input_rank(room->user_id[0], 3);
		}
	}
	else if (user1_win) {
		write(room->clnt_sock[1], "/lose\n", strlen("/lose\n"));
		write(room->clnt_sock[0], "/win\n", strlen("/win\n"));
		printf("%s win %s lose\n", room->user_id[0], room->user_id[1]);
		sprintf(log_msg, "%s win %s lose\n", room->user_id[0], room->user_id[1]);
		write(log_fds[1], log_msg, strlen(log_msg));
		//input_rank(room->user_id[1], 3);
		//input_rank(room->user_id[0], 1);
	}
	memset(&(room->gameController), 0, sizeof(room->gameController));  
	return 0;
}



int rw_login_db(char* rw, char* id, char* pw) {
	FILE* fp = NULL;
	FILE* rank_fp = NULL;
	char mode[5];
	char uid[USER_ID_SIZE] = { 0, };
	char upw[USER_ID_SIZE] = { 0, };
	char get_id[USER_ID_SIZE] = { 0, };
	char get_pw[USER_ID_SIZE] = { 0, };
	int is_duplicated_id = 0;
	int result = 0;

	memcpy(mode, rw, strlen(rw));
	memcpy(uid, id, strlen(id));
	memcpy(upw, pw, strlen(pw));

	pthread_mutex_lock(&login_db_mutx); // login_db.txt mutx lock
	if ((fp = fopen("login_db.txt", mode)) == NULL) {
		error_handling("fopen(loin.txt) error");
	}
	printf("\ndb connect!\n");
	if (strncmp(mode, "r", strlen(mode)) == 0) {   
	   // login_db.txt 
		while (fscanf(fp, "%s %s\n", get_id, get_pw) != EOF) {
			if (strncmp(uid, get_id, strlen(get_id)) == 0) {   
				printf("ID match\n");
				if (strncmp(upw, get_pw, strlen(get_pw)) == 0) {   
					printf("PW match\n");
					result = 1;   // true
				}
			}
		}
	}
	else if (strncmp(mode, "r+", strlen(mode)) == 0) {   
	   // login_db.txt 
		while (fscanf(fp, "%s %s\n", get_id, get_pw) != EOF) {
			if (strncmp(uid, get_id, strlen(get_id)) == 0) {   
				printf("ID already exit\n");
				is_duplicated_id = 1;            
				break;
			}
		}
		
		if (!(is_duplicated_id)) {
			printf("Account registration\n");
			fprintf(fp, "%s %s\n", uid, upw);   // login_db.txt
			if ((rank_fp = fopen("ranking_db.txt", "at+")) == NULL) {   // rankig_db.txt open
				error_handling("fopen() error");
			}
			fprintf(rank_fp, "%s 0 0 0\n", uid);   
			fclose(rank_fp);            // ranking_db.txt close
			result = 1;   // true
		}
	}
	fclose(fp);                     // login_db.txt close
	pthread_mutex_unlock(&login_db_mutx); // login_db.txt mutx unlock

	return result;   // Y == 1 or N == 0
}

