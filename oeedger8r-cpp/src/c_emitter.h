// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef C_EMITTER_H
#define C_EMITTER_H

#include <fstream>

#include "ast.h"
#include "f_emitter.h"
#include "utils.h"
#include "w_emitter.h"

#include "pop_w_emiiter.h"

class CEmitter
{
    Edl* edl_;
    bool gen_t_c_;
    std::ofstream file_;
    std::string indent_;

  public:
    typedef CEmitter& R;
    R out()
    {
        return *this;
    }

    template <typename T>
    R operator<<(const T& t)
    {
        file_ << indent_ << t << "\n";
        return out();
    }
    template <typename T>
    R operator<<(const T* t)
    {
        if (t)
            file_ << indent_ << t << "\n";
        return out();
    }

  public:
    CEmitter(Edl* edl) : edl_(edl), gen_t_c_(false), file_(), indent_()
    {
    }

    void emit_t_c(const std::string& dir_with_sep = "")
    {
        gen_t_c_ = true;
        file_.open(dir_with_sep + edl_->name_ + "_t.c");
        autogen_preamble(out());
        out() << "#include \"" + edl_->name_ + "_t.h\""
              << ""
              << "#include <openenclave/edger8r/enclave.h>"
              << ""
              << "OE_EXTERNC_BEGIN"
              << ""
              << "/* Set to false to bypass secure unserializing ocall return "
                 "values */"
              << "OE_WEAK bool oe_edger8r_secure_unserialize = true;"
              << ""
              << "/**** Trusted function IDs ****/";
        trusted_function_ids();
        out() << "/**** ECALL marshalling structs. ****/";
        ecall_marshalling_structs();
        out() << "/**** ECALL functions. ****/"
              << "";
        for (Function* f : edl_->trusted_funcs_)
            emit_forwarder(f);
        out() << "/**** ECALL function table. ****/"
              << "";
        ecalls_table();
        out() << "/**** Untrusted function IDs. ****/";
        untrusted_function_ids();
        out() << "/**** OCALL marshalling structs. ****/";
        ocall_marshalling_structs();
        out() << "/**** OCALL function wrappers. ****/"
              << "";
        for (Function* f : edl_->untrusted_funcs_)
            emit_wrapper(f);
        if (edl_->untrusted_funcs_.empty())
            out() << "/* There were no ocalls. */";
        out() << "OE_EXTERNC_END";
        file_.close();
    }

    void emit_u_c(
        const std::string& dir_with_sep = "",
        const std::string& prefix = "", bool is_popsgx_server = false)
    {
        gen_t_c_ = false;
        file_.open(dir_with_sep + edl_->name_ + "_u.c");
        autogen_preamble(out());
        out() << "#include \"" + edl_->name_ + "_u.h\""
              << ""
              << "#include <openenclave/edger8r/host.h>"
              << "";

        if(is_popsgx_server){
            out() << ""
                  << "#include <stdio.h>"
                  << "#include <netdb.h>"
                  << "#include <netinet/in.h>"
                  << "#include <stdlib.h>"
                  << "#include <string.h>"
                  << "#include <sys/socket.h>"
                  << "#include <sys/types.h>"
                  << "#include <unistd.h> // read(), write(), close()"
                  << "#define MAX 80"
                  << "#define PORT 8080"
                  << "#define SA struct sockaddr"
                  << "";
        }else{
            out() << ""
                  << "#include <arpa/inet.h> // inet_addr()"
                  << "#include <netdb.h>"
                  << "#include <stdio.h>"
                  << "#include <stdlib.h>"
                  << "#include <string.h>"
                  << "#include <strings.h> // bzero()"
                  << "#include <sys/socket.h>"
                  << "#include <unistd.h> // read(), write(), close()"
                  << "#define MAX 80"
                  << "#define PORT 8080"
                  << "#define SA struct sockaddr"
                  << "";
        }

        out()     << "OE_EXTERNC_BEGIN"
                  << ""
                  << "/**** Trusted function IDs. ****/";
        
        trusted_function_ids();
        out() << "/**** PopSGX send/rcv functions. ****/";
        popsgx_send_recv_helper();
        out() << "/**** Trusted function names. ****/";
        trusted_function_names();
        out() << "/**** ECALL marshalling structs. ****/";
        ecall_marshalling_structs();
        out() << "/**** ECALL function wrappers. ****/"
              << "";
        for (Function* f : edl_->trusted_funcs_)
            emit_wrapper(f, prefix, is_popsgx_server);
        out() << "/**** Untrusted function IDs. ****/";
        untrusted_function_ids();
        out() << "/**** OCALL marshalling structs. ****/";
        ocall_marshalling_structs();
        out() << "/**** OCALL functions. ****/"
              << "";
        for (Function* f : edl_->untrusted_funcs_)
            emit_forwarder(f);
        if (edl_->untrusted_funcs_.empty())
            out() << "/* There were no ocalls. */"
                  << "";
        out() << "/**** OCALL function table. ****/"
              << "";
        ocalls_table();
        out() << "/**** PopSGX ECALL function wrappers. ****/";
        
        if(is_popsgx_server){
            for(Function *f : edl_->trusted_funcs_)
                emit_pop_wrapper(f, "popsgx");
            popsgx_server();
            popsgx_main();
            out() << create_prototype(edl_->name_) << "{"
              << "    oe_result_t ret = OE_FAILURE;"
              << "    ret = popsgx_main("
              << "               path,"
              << "               type,"
              << "               flags,"
              << "               settings,"
              << "               setting_count,"
              << "               enclave);"
              << ""
              << "    //It should never return here"
              << "    return ret;"
              << ""
              << "/*"
              << "    return oe_create_enclave("
              << "               path,"
              << "               type,"
              << "               flags,"
              << "               settings,"
              << "               setting_count,"
              << "               _" + edl_->name_ + "_ocall_function_table,"
              << "               " + to_str(edl_->untrusted_funcs_.size()) + ","
              << "               _" + edl_->name_ + "_ecall_info_table,"
              << "                " + to_str(edl_->trusted_funcs_.size()) + ","
              << "               enclave);"
              << "*/"
              << "}"
              << ""
              << "OE_EXTERNC_END";
        }
        else
        {
            popsgx_client();
            out() << create_prototype(edl_->name_) << "{"
              << "    oe_result_t ret = OE_FAILURE;"
              << "    ssize_t bytes_sent, bytes_received;"
              << ""
              << "    int buffer = -1; // We will use -1 to initiate the enclave as of now"
              << "    unsigned long int enclave_id = -1;"
              << "    static bool is_initial = true;"
              << " "
              << "    if(is_initial){"
              << "        ret = connect_popsgx_server(&connfd);"
              << "        if(ret != OE_OK)"
              << "            return ret;"
              << ""
              << "        is_initial = false;"
              << "    }"
              << " "
              << "    bytes_sent = popsgx_send(connfd, &buffer, sizeof(buffer));"
              << "    if (bytes_sent != sizeof(buffer)) {"
              << "        close(connfd);"
              << "        return OE_FAILURE;    "
              << "    }"
              << " "
              << "    bytes_received = popsgx_read(connfd, &ret, sizeof(ret));"
              << "    if (bytes_received <= 0){"
              << "        perror(\"Server response failed\");"
              << "        close(connfd);"
              << "        return OE_FAILURE;"
              << "    }"
              << ""
              << "    bytes_received = popsgx_read(connfd, &enclave_id, sizeof(unsigned long int));"
              << "    if(bytes_received != sizeof(unsigned long int)){"
              << "        perror(\"Failed to create an enclave\");"
              << "        close(connfd);"
              << "        return OE_FAILURE;"
              << "    }"
              << ""
              << "    *enclave = (oe_enclave_t*)enclave_id;"
              << ""
              << "    return ret;"
              << ""
              << "/*"
              << "    return oe_create_enclave("
              << "               path,"
              << "               type,"
              << "               flags,"
              << "               settings,"
              << "               setting_count,"
              << "               _" + edl_->name_ + "_ocall_function_table,"
              << "               " + to_str(edl_->untrusted_funcs_.size()) + ","
              << "               _" + edl_->name_ + "_ecall_info_table,"
              << "                " + to_str(edl_->trusted_funcs_.size()) + ","
              << "               enclave);"
              << "*/"
              << "}"
              << ""
              << "OE_EXTERNC_END";            
        }
            
        
        
        file_.close();
    }

    void trusted_function_ids()
    {
        out() << "enum"
              << "{";
        int idx = 0;
        std::string pfx = "    " + edl_->name_ + "_fcn_id_";
        for (Function* f : edl_->trusted_funcs_)
            out() << pfx + f->name_ + " = " + to_str(idx++) + ",";
        out() << pfx + "trusted_call_id_max = OE_ENUM_MAX"
              << "};"
              << "";
    }

    void trusted_function_names()
    {
        out() << "static const oe_ecall_info_t _" + edl_->name_ +
                     "_ecall_info_table[] = "
              << "{";
        for (Function* f : edl_->trusted_funcs_)
            out() << "    { \"" + f->name_ + "\" },";
        out() << "};"
              << "";
    }

    void untrusted_function_ids()
    {
        out() << "enum"
              << "{";
        int idx = 0;
        std::string pfx = "    " + edl_->name_ + "_fcn_id_";
        for (Function* f : edl_->untrusted_funcs_)
            out() << pfx + f->name_ + " = " + to_str(idx++) + ",";
        out() << pfx + "untrusted_call_max = OE_ENUM_MAX"
              << "};"
              << "";
    }

    void ecall_marshalling_structs()
    {
        for (Function* f : edl_->trusted_funcs_)
            marshalling_struct(f, false);
    }

    void ocall_marshalling_structs()
    {
        for (Function* f : edl_->untrusted_funcs_)
            marshalling_struct(f, true);
    }

    void marshalling_struct(Function* f, bool ocall = false)
    {
        bool has_deep_copy_out_param = has_deep_copy_out(edl_, f);
        (void)ocall;
        out() << "typedef struct _" + f->name_ + "_args_t"
              << "{"
              << "    oe_result_t oe_result;"
              << "    uint8_t* deepcopy_out_buffer;"
              << "    size_t deepcopy_out_buffer_size;";
        indent_ = "    ";
        if (f->rtype_->tag_ != Void)
            out() << atype_str(f->rtype_) + " oe_retval;";
        for (Decl* p : f->params_)
        {
            out() << mdecl_str(p->name_, p->type_, p->dims_, p->attrs_) + ";";
            if (p->attrs_ && (p->attrs_->string_ || p->attrs_->wstring_))
                out() << "size_t " + p->name_ + "_len;";
        }
        if (f->errno_)
            out() << "int ocall_errno;";
        indent_ = "";
        out() << "} " + f->name_ + "_args_t;"
              << "";
    }

    void ecalls_table()
    {
        out() << "oe_ecall_func_t oe_ecalls_table[] = {";
        size_t idx = 0;
        for (Function* f : edl_->trusted_funcs_)
            out() << "    (oe_ecall_func_t) ecall_" + f->name_ +
                         (++idx < edl_->trusted_funcs_.size() ? "," : "");
        out() << "};"
              << ""
              << "size_t oe_ecalls_table_size = "
                 "OE_COUNTOF(oe_ecalls_table);"
              << "";
    }

    void ocalls_table()
    {
        out() << "static oe_ocall_func_t _" + edl_->name_ +
                     "_ocall_function_table[] = {";
        for (Function* f : edl_->untrusted_funcs_)
            out() << "    (oe_ocall_func_t) ocall_" + f->name_ + ",";
        out() << "    NULL"
              << "};"
              << "";
    }

    void emit_forwarder(Function* f)
    {
        FEmitter(edl_, file_).emit(f, gen_t_c_);
    }

    void emit_wrapper(Function* f, const std::string& prefix = "", bool is_popsgx_server = true)
    {
        WEmitter(edl_, file_).emit(f, !gen_t_c_, prefix, is_popsgx_server);
    }

    void emit_pop_wrapper(Function* f, const std::string& prefix = "popsgx")
    {
        PopWEmitter(edl_, file_).emit(f, !gen_t_c_, prefix);
    }

    void popsgx_send_recv_helper()
    {
        out()<<""
             <<"enum ConnectionState {"
             <<"    STATE_OE_CREATE,"
             <<"    STATE_OE_ECALLS,"
             <<"    STATE_CUSTOM1,"
             <<"    STATE_CUSTOM2,"
             <<"    // Add more states as needed"
             <<"};"
             <<""
             <<"static int connfd;"
             <<""
             <<"static int popsgx_read(int sk, void* dest, int bytes_expected){"
             <<"    int bytes_received = 0;"
             <<"    char *temp = (char*)dest;"
             <<""
             <<"    while(bytes_received < bytes_expected){"
             <<"        int bytes = recv(sk, temp + bytes_received, bytes_expected - bytes_received, 0);"
             <<"        if(bytes < 0){"
             <<"	    perror(\"pop_sgx read failed\");"
             <<"	    return bytes;"
             <<"	}"
             <<"	bytes_received += bytes;"
             <<"    }"
             <<""
             <<"    return bytes_received;"
             <<"}"
             <<""
             <<"static int popsgx_send(int sk, const void* src, int bytes_to_send) {"
             <<"    int bytes_sent = 0;"
             <<"    const char *temp = (const char*)src;"
             <<""
             <<"    while (bytes_sent < bytes_to_send) {"
             <<"        int bytes = send(sk, temp + bytes_sent, bytes_to_send - bytes_sent, 0);"
             <<"        if (bytes < 0) {"
             <<"            perror(\"pop_sgx send failed\");"
             <<"            return bytes;"
             <<"        }"
             <<"        bytes_sent += bytes;"
             <<"    }"
             <<""
             <<"    return bytes_sent;"
             <<"}"
             <<"";
    }

    void popsgx_main(){
        out()         <<""
                      <<"oe_result_t popsgx_main(const char* path,"
                      <<"    oe_enclave_type_t type,"
                      <<"    uint32_t flags,"
                      <<"    const oe_enclave_setting_t* settings,"
                      <<"    uint32_t setting_count,"
                      <<"    oe_enclave_t** enclave){"
                      <<"    "
                      <<"    int ret = 0;"
                      <<"    oe_result_t oe_ret = OE_FAILURE;"
                      <<"    enum ConnectionState state = STATE_OE_CREATE;"
                      <<"    int buffer;"
                      <<"    ssize_t bytes_received, bytes_sent;"
                      <<"    "
                      <<"    unsigned long int enclave_id = 1;"
                      <<"    oe_enclave_t* p_enclave[100] = {NULL};"
                      <<"    "
                      <<"    //Below will only return if its valid"
                      <<"    connfd = create_popsgx_server();"
                      <<"    "
                      <<"    while(1){"
                      <<"        unsigned long int _temp_enclave_id = -1;"
                      <<"        bytes_received = popsgx_read(connfd, &buffer, sizeof(buffer));"
                      <<"        if(bytes_received != sizeof(buffer)){"
                      <<"            close(connfd);"
                      <<"            break;"
                      <<"        }"
                      <<""
                      <<"        if(buffer == -1)"
                      <<"            state = STATE_OE_CREATE;"
                      <<""
                      <<"        switch (state) {"
                      <<"            case STATE_OE_CREATE:"
                      <<"                oe_ret = oe_create_enclave("
                      <<"                           path,"
                      <<"                           type,"
                      <<"                           flags,"
                      <<"                           settings,"
                      <<"                           setting_count,"
                      <<"                           _" + edl_->name_ + "_ocall_function_table,"
                      <<"                           " + to_str(edl_->untrusted_funcs_.size()) + ","
                      <<"                           _" + edl_->name_ + "_ecall_info_table,"
                      <<"                            " + to_str(edl_->trusted_funcs_.size()) + ","
                      <<"                           &p_enclave[enclave_id]);"
                      <<""
                      <<"                bytes_sent = popsgx_send(connfd, &oe_ret, sizeof(oe_ret));"
                      <<"                if(bytes_sent != sizeof(oe_ret)){"
                      <<"                    close(connfd);"
                      <<"                    return OE_FAILURE;"
                      <<"                }"
                      <<""    
                      <<"                bytes_sent = popsgx_send(connfd, &enclave_id, sizeof(unsigned long int));"
                      <<"                if (bytes_sent != sizeof(unsigned long int)){"
                      <<"                    close(connfd);"
                      <<"                    return OE_FAILURE;"
                      <<"                }"
                      <<""
                      <<"                enclave_id++;"
                      <<"                state = STATE_OE_ECALLS;"
                      <<"                break;"
                      <<""
                      <<"           case  STATE_OE_ECALLS:"
                      <<"               ////Have to check if a valid function is being called!!"
                      <<"               oe_ret = OE_OK;"
                      <<"               bytes_sent = popsgx_send(connfd, &oe_ret, sizeof(oe_ret));"
                      <<"               if (bytes_sent != sizeof(oe_ret)) {"
                      <<"                   close(connfd);"
                      <<"                   return OE_FAILURE;"
                      <<"               }"
                      <<""
                      <<"               bytes_received = popsgx_read(connfd, &_temp_enclave_id, sizeof(unsigned long int));"
                      <<"               if(bytes_received != sizeof(unsigned long int)){"
                      <<"                   close(connfd);"
                      <<"                   return OE_FAILURE;"
                      <<"               }"
                      <<"";
        int idx = 0;
        for(Function* f : edl_->trusted_funcs_){
            std::string pfx = "popsgx_";
            if(idx == 0)
                out() <<"               if(buffer == " + to_str(idx++) + "){";
            else    
                out() <<"               else if(buffer== " + to_str(idx++) + "){";
                
            out()     <<"                   oe_ret = " + pfx + f->name_ +"(p_enclave[_temp_enclave_id]);"
                      <<"                   if(oe_ret == OE_FAILURE){"
                      <<"                       return oe_ret;"
                      <<"                   }"
                      <<"               }";
        }
        out()         <<""    
                      <<"               break;"
                      <<"        }"
                      <<"    };"
                      <<"}"
                      <<"";
    }

    void popsgx_client()
    {
        out()<<"oe_result_t connect_popsgx_server(int *connfd){"
             <<"    int sockfd;"
             <<"    struct sockaddr_in servaddr, cli;"
             <<" "
             <<"    // socket create and verification"
             <<"    sockfd = socket(AF_INET, SOCK_STREAM, 0);"
             <<"    if (sockfd == -1) {"
             <<"        printf(\"socket creation failed...\\n\");"
             <<"        return OE_FAILURE;"
             <<"    }"
             <<"    else"
             <<"        printf(\"Socket successfully created..\\n\");"
             <<"    bzero(&servaddr, sizeof(servaddr));"
             <<" "
             <<"    // assign IP, PORT"
             <<"    servaddr.sin_family = AF_INET;"
             <<"    servaddr.sin_addr.s_addr = inet_addr(\"127.0.0.1\");"
             <<"    servaddr.sin_port = htons(PORT);"
             <<" "
             <<"    // connect the client socket to server socket"
             <<"    if (connect(sockfd, (SA*)&servaddr, sizeof(servaddr))"
             <<"        != 0) {"
             <<"        printf(\"connection with the server failed...\\n\");"
             <<"        return OE_FAILURE;"
             <<"    }"
             <<"    else"
             <<"        printf(\"connected to the server..\\n\");"
             <<"    "
             <<"    *connfd = sockfd;"
             <<""
             <<"    return OE_OK;"
             <<"}"
             <<"";
    }

    void popsgx_server()
    {
        out()<<"int create_popsgx_server(void){"
             <<"    int sockfd, connfd, len;"
             <<"    struct sockaddr_in servaddr, cli;"
             <<""
             <<"    // socket create and verification"
             <<"    sockfd = socket(AF_INET, SOCK_STREAM, 0); "
             <<"    if (sockfd == -1) { "
             <<"        printf(\"socket creation failed...\\n\"); "
             <<"        exit(0); "
             <<"    } "
             <<"    else"
             <<"        printf(\"Socket successfully created..\\n\"); "
             <<"    bzero(&servaddr, sizeof(servaddr)); "
             <<"    "
             <<"    // assign IP, PORT "
             <<"    servaddr.sin_family = AF_INET; "
             <<"    servaddr.sin_addr.s_addr = htonl(INADDR_ANY); "
             <<"    servaddr.sin_port = htons(PORT); "
             <<"    "
             <<"    // Binding newly created socket to given IP and verification "
             <<"    if ((bind(sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0) { "
             <<"        printf(\"socket bind failed...\\n\"); "
             <<"        exit(0); "
             <<"    } "
             <<"    else"
             <<"        printf(\"Socket successfully binded..\\n\"); "
             <<"    "
             <<"    // Now server is ready to listen and verification "
             <<"    if ((listen(sockfd, 5)) != 0) { "
             <<"        printf(\"Listen failed...\\n\"); "
             <<"        exit(0); "
             <<"    } "
             <<"    else"
             <<"        printf(\"Server listening..\\n\"); "
             <<"    len = sizeof(cli); "
             <<"    "
             <<"    // Accept the data packet from client and verification "
             <<"    connfd = accept(sockfd, (SA*)&cli, &len); "
             <<"    if (connfd < 0) { "
             <<"        printf(\"server accept failed...\\n\"); "
             <<"        exit(0); "
             <<"    } "
             <<"    else"
             <<"        printf(\"server accept the client...\\n\");"
             <<"    "
             <<"    return connfd; "
             <<"}"
             <<"";  
    }
};

#endif // C_EMITTER_H
