#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "threadpool.h"
#define BUFFER 8192


char *extract_first_line(const char *request, char *first_line) {
    const char *end_of_first_line = strstr(request, "\r\n");
    if (end_of_first_line == NULL) {
        return NULL; //unable to find the end of the first line
    }
    size_t first_line_length = end_of_first_line - request;
    if (first_line_length >= strlen(first_line)) {
        strncpy(first_line, request, first_line_length);
        first_line[first_line_length] = '\0'; //null-terminate the first line
        return first_line;
    }
    return NULL; //buffer overflow might occur
}

int check_host_header(const char *request) {
    //find the Host header line
    const char *host_line_start = strstr(request, "Host:");
    if (host_line_start == NULL) {
        return 0;
    }

    //find the end of the line
    const char *end_of_line = strstr(host_line_start, "\r\n");
    if (end_of_line == NULL) {
        return 0;
    }

    //calculate the length of the hostname
    size_t hostname_length = end_of_line - (host_line_start + 6); // 6 is the length of "Host: "

    //check if the hostname is empty
    if (hostname_length == 0) {
        return 0;
    }

    return 1; //host header is present and has a non-empty value
}

//function to check if the request line has exactly three parts (method, path, protocol)
int check_request_line(char *request) {
    char *token;
    int count = 0;

    token = strtok(request, " ");
    while (token != NULL) {
        count++;
        token = strtok(NULL, " ");
    }

    //return 1 if exactly three tokens are found(method, path, and protocol)
    return count;
}

typedef struct {
    struct sockaddr_in sockinfo;
    int sockfd;
    char filter_path[256];
} CLIENT_INFO;


//function to check if the requested URL (host name or IP address) is forbidden
int check_filter(const char *url, FILE *file) {
    if (file == NULL) {
        perror("Invalid filter file");
        return 0; //return 0 as there was an error opening the file
    }

    char line[BUFFER];
    while (fgets(line, BUFFER, file) != NULL) {
        //trim newline character
        strtok(line, "\r\n");

        //check if the URL matches any entry in the filter file
        if (strcmp(url, line) == 0) {
            return 1; //return 1 if the URL is found in the filter file
        }

        //check if the URL is an IP address or hostname
        struct in_addr requested_ip;
        if (inet_aton(url, &requested_ip) == 0) {
            //URL is a hostname
            //convert hostname to IP address
            struct hostent *he = gethostbyname(url);
            if (he == NULL) {
                continue; //move to the next line in the filter file
            }
            requested_ip = *((struct in_addr *)he->h_addr);
        }

        //check if the URL matches any entry in the filter file
        if (strcmp(inet_ntoa(requested_ip), line) == 0) {
            return 1; //return 1 if the URL is found in the filter file
        }

        //check if the URL is an IP address and matches any subnet in the filter file
        char *subnet = strchr(line, '/');
        if (subnet != NULL) {
            *subnet = '\0'; //split IP address and subnet mask
            char *ip_address = line;
            char *subnet_mask = subnet + 1;

            struct in_addr filter_ip;
            inet_aton(ip_address, &filter_ip);

            int mask_bits = atoi(subnet_mask);
            uint32_t filter_network = ntohl(filter_ip.s_addr) & (0xFFFFFFFF << (32 - mask_bits));
            uint32_t requested_network = ntohl(requested_ip.s_addr) & (0xFFFFFFFF << (32 - mask_bits));

            if (filter_network == requested_network) { //return 1 if the IP address matches the subnet
                return 1;
            }
        }
    }

    return 0; //return 0 if the URL is not found in the filter file
}


void construct_error_response(char *response, const char *error_code, const char *error_message, const char *additional_message) {

    //clear the response buffer
    memset(response, 0, BUFFER*2);
    //get the current date and time
    time_t now = time(NULL);
    struct tm *tm_now = localtime(&now);
    if (tm_now == NULL) {
        //handle null return from localtime
        fprintf(stderr, "Error: localtime returned null\n");
        return;
    }
    char date_str[64];
    if (strftime(date_str, sizeof(date_str), "%a, %d %b %Y %H:%M:%S GMT", tm_now) == 0) {
        //handle error in strftime
        fprintf(stderr, "Error: strftime returned 0\n");
        return;
    }

    //HTML content
    char html_content[BUFFER];
    snprintf(html_content, sizeof(html_content), "<HTML><HEAD><TITLE>%s %s</TITLE></HEAD>\r\n"
                                                 "<BODY><H4>%s %s</H4>\r\n"
                                                 "%s\r\n"
                                                 "</BODY></HTML>",
             error_code, error_message, error_code, error_message , additional_message);
    //remove invalid characters at the end of the response string
    int len = strlen(response);
    while (len > 0 && (response[len - 1] == '\n' || response[len - 1] == '\r')) {
        response[len - 1] = '\0';
        len--;
    }
    //calculate content length
    int content_length = strlen(html_content);

    //construct the HTTP response
    snprintf(response, BUFFER*2,
             "HTTP/1.1 %s %s\r\n"
             "Server: webserver/1.0\r\n"
             "Date: %s\r\n"
             "Content-Type: text/html\r\n"
             "Content-Length: %d\r\n"
             "Connection: close\r\n"
             "\r\n"
             "%s",
             error_code, error_message, date_str, content_length, html_content);
    // ensure null termination
    response[(BUFFER*2) - 1] = '\0';
}


void handle_response(void* arg) {
    CLIENT_INFO *cinfo = (CLIENT_INFO *) arg;
    char buf[BUFFER];
    int err_flag = 0;
    memset(&buf, 0, sizeof(buf));
    int bytes_read = 0;
    char copy[BUFFER * 2];
    char response[BUFFER * 2];
    memset(&response, 0, sizeof(response));
    //read the HTTP request from the client
    bytes_read = read(cinfo->sockfd, buf, BUFFER);
    strcpy(copy, buf);
    int hostF=0;
    //extract the host from the HTTP request
    char *host_start = strstr(buf, "Host: ");
    if (host_start == NULL) {
        hostF=1;
    }
    //check if "Connection: keep-alive" exists and modify the request accordingly
    char *connection_header = strstr(copy, "Connection: keep-alive");
    if (connection_header) {
        //find the end of the line after the header
        char *end_of_line = strstr(connection_header, "\r\n");
        if (end_of_line) {
            //overwrite with "Connection: close"
            memcpy(connection_header, "Connection: close", strlen("Connection: close"));
            //delete characters after "Connection: close"
            memmove(connection_header + strlen("Connection: close"), end_of_line, strlen(end_of_line) + 1);
        }
    } else {
        //if "Connection: keep-alive" doesn't exist, append "Connection: close" to the request
        strcat(copy, "Connection: close\r\n");
    }

    strcpy(response, copy);
//    printf("received:\n%s\n",response);


    //extract the host from the HTTP request
    char copyBuff[BUFFER * 2];
    strcpy(copyBuff, copy);
    copyBuff[strlen(copyBuff) - 1] = '\0';
    char first_line[BUFFER];
    memset(first_line, 0, sizeof(first_line)); //initialize first_line with null characters
    //extract the first line of the request
    char *first_line_ptr = extract_first_line(copy, first_line);

    int check = check_host_header(copy);
    //create a new HTTP request with correct format
    char *duplic = strstr(copyBuff, "http://");
    char *slash = NULL;
    char *tempSpace = NULL;
    int dFlag=0;
    if (duplic != NULL) {
        dFlag=1;
        slash = strstr(duplic + 8, "/");
        tempSpace = strstr(duplic, " ");
    } else {
        dFlag=2;
        slash = strstr(copyBuff, "/");
        tempSpace = strstr(copyBuff, " ");
    }
    int slashF=0;
    if(slash!=NULL){
        slashF=1;
    }
    else{
        if(strchr(copyBuff,'/')==NULL) {
//            printf("\n***CHECK Slash:%s***\n",strchr(copyBuff,'/'));
            slashF = 2;
        }
    }



    char *space = strchr(copyBuff, ' ');
    char filepath[100], method[20],newProtocol[8];


    memset(filepath, 0, sizeof(filepath));
    memset(method, 0, sizeof(method));
//    memset(protocol, 0, sizeof(protocol));
    //calculate the length of the method string
    size_t method_len = space - copyBuff;

    size_t filepath_len = tempSpace - slash; //calculate the length of the filepath string
//    size_t protocol_len = 8;
    if(dFlag==2){
        filepath_len= 6;
    }


    if(slashF==1) {

        // Copy the filepath string
        strncpy(filepath, slash, filepath_len);
//        printf("***FILEPATH:%s***\n",filepath);
        filepath[filepath_len] = '\0'; //null-terminate the filepath string// Null-terminate the host string
    }
    else if(slashF==2){
        filepath[0]='\0';
    }

    //copy the method string
    strncpy(method, copyBuff, method_len);
    method[method_len] = '\0'; //null-terminate the method string
    // Copy the protocol string
   char *protocol= strstr(copyBuff,"HTTP/");
//   ssize_t protocol_len=protocol-rn;
    strncpy(newProtocol, protocol, (ssize_t)8);
    newProtocol[7] = '\0'; //null-terminate the protocol string
//    printf("***%s*\n",method);
     if (strcmp(method, "GET") != 0) {
        err_flag = 1;
        construct_error_response(response, "501", "Not supported", "Method is not supported.");
    }
     else if (check_request_line(first_line_ptr) != 3 || filepath[0] == '\0' ||
        ( strcmp(newProtocol, "HTTP/1.") != 0)
        || check == 0 || hostF==1 ) {
        err_flag = 1;
        construct_error_response(response, "400", "Bad Request", "Bad Request.");
    }


//    printf("***HERE");
    struct hostent *server;
    if(hostF==0 ) {
        host_start += 6;  //skip "Host: "
        char *host_end = strchr(host_start, '\r');
        if (host_end == NULL) {
            fprintf(stderr, "Invalid request format\n");
            close(cinfo->sockfd);
            free(cinfo);
            return;
        }
        *host_end = '\0';

        //remove "http://" prefix from the host if present
        char *http_prefix = "http://";
        if (strncmp(host_start, http_prefix, strlen(http_prefix)) == 0) {
            host_start += strlen(http_prefix);
        }
        server = gethostbyname(host_start);
        if (server == NULL && err_flag==0) {
            herror("gethostbyname failed");
            err_flag = 1;
            construct_error_response(response, "404", "Not Found", "File not found.");
 }
    }




    //open the filter file
    FILE *filter_file = fopen(cinfo->filter_path, "r");
    if (filter_file == NULL) {
        perror("fopen");
        close(cinfo->sockfd);
        free(cinfo);
        return;
    }

    //check if the requested URL is forbidden based on the filter file
    if (check_filter(host_start, filter_file)) {
        err_flag=1;
        construct_error_response(response,"403","Forbidden","Access denied.");
    }

    //close the filter file
    fclose(filter_file);
    if (err_flag == 0) {

        //create a TCP socket to connect to the target server
        int server_sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (server_sockfd < 0) {
            perror("socket");
            close(cinfo->sockfd);
            free(cinfo);
            return;
        }


        //initialize the server address struct
        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        bcopy((char *) server->h_addr, (char *) &server_addr.sin_addr.s_addr, server->h_length);
        server_addr.sin_port = htons(80);

        //connect to the server
        if (connect(server_sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
            construct_error_response(response,"500","Internal Server Error","Some server side error.");
            goto client;
        }
        if (write(server_sockfd, response, bytes_read) < 0) {
            construct_error_response(response,"500","Internal Server Error","Some server side error.");
            goto client;
        }

        while ((bytes_read = recv(server_sockfd, response, BUFFER, 0)) > 0) {
            if (write(cinfo->sockfd, response, bytes_read) < 0) {
                perror("write");
                break;
            }

        }
        close(server_sockfd);
    } else {
        client:
//        printf("RESONSE:%s\n",response);
        if (write(cinfo->sockfd, response, sizeof(response)) < 0) {
            perror("write");

        }

        if (bytes_read < 0) {
            perror("recv");
        }



    }
    close(cinfo->sockfd);
    free(cinfo);
}
int main(int argc, char* argv[]) {
    if (argc != 5) {
        printf("Usage: proxyServer <port> <pool-size> <max-number-of-request> <filter>\n");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in serverinfo;
    int wsock;
    in_port_t port = (in_port_t)strtoul(argv[1], NULL, 10);
//   in_port_t port=3010;
    size_t pool = strtoul(argv[2], NULL, 10);
//    size_t pool=4;
    size_t max_tasks = strtoul(argv[3], NULL, 10);
//    size_t max_tasks=10;
        char *path=argv[4];
//    char *path="filter.txt";

    //create a thread pool with maximum 5 threads
    threadpool* tp = create_threadpool(pool);
    if (tp == NULL) {
        fprintf(stderr, "Failed to initialize thread pool.\n");
        exit(EXIT_FAILURE);
    }



    // Ensure num_of_tasks does not exceed max_tasks
    pool = pool > max_tasks ? max_tasks : pool;
    //initialize serverinfo
    memset(&serverinfo, 0, sizeof(struct sockaddr_in));
    serverinfo.sin_family = AF_INET;
    serverinfo.sin_port = htons(port);
    serverinfo.sin_addr.s_addr = htonl(INADDR_ANY);



    // Create a TCP socket
    if ((wsock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    // Bind socket
    if (bind(wsock, (struct sockaddr*)&serverinfo, sizeof(struct sockaddr_in)) == -1) {
        close(wsock);
        perror("bind");
        exit(EXIT_FAILURE);
    }
    // Listen for incoming connections
    if (listen(wsock, 5) == -1) {
        close(wsock);
        perror("listen");
        exit(EXIT_FAILURE);
    }
    // Accept incoming connections and dispatch tasks
    // Connect to the server

    for (size_t i = 0; i < max_tasks; i++) {

        CLIENT_INFO* cinfo = (CLIENT_INFO*)malloc(sizeof(CLIENT_INFO));
        socklen_t struct_len = sizeof(struct sockaddr_in);

        cinfo->sockfd = accept(wsock, (struct sockaddr*)&cinfo->sockinfo, &struct_len);

        if (cinfo->sockfd == -1) {
            perror("accept");
            free(cinfo);
            continue;
        }
        strcpy(cinfo->filter_path,path);
        dispatch(tp, (dispatch_fn) handle_response, (void*)cinfo);
    }


    //destroy the thread pool and close the socket
    destroy_threadpool(tp);
    close(wsock);
    return 0;
}
