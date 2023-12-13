#ifndef POP_W_EMITTER_H
#define POP_W_EMITTER_H

#include <fstream>

#include "ast.h"
#include "utils.h"

class PopWEmitter
{
    Edl* edl_;
    std::ofstream& file_;
    bool ecall_;
    bool has_deep_copy_out_;

  public:
    typedef PopWEmitter& R;
    R out()
    {
        return *this;
    }

    template <typename T>
    R operator<<(const T& t)
    {
        file_ << t << "\n";
        return out();
    }

  public:
    
    PopWEmitter(Edl* edl, std::ofstream& file)
        : edl_(edl), file_(file), ecall_(true)
    {
    }

    bool gen_t() const
    {
        return !ecall_;
    }

    void get_functions(
        Function* f,
        std::string& alloc_fcn,
        std::string& free_fcn,
        std::string& call)
    {
        if (f->switchless_)
        {
            if (!ecall_)
            {
                alloc_fcn = "oe_allocate_switchless_ocall_buffer";
                free_fcn = "oe_free_switchless_ocall_buffer";
                call = "oe_switchless_call_host_function";
            }
            else
            {
                alloc_fcn = "oe_malloc";
                free_fcn = "oe_free";
                call = "oe_switchless_call_enclave_function";
            }
        }
        else
        {
            if (!ecall_)
            {
                alloc_fcn = "oe_allocate_ocall_buffer";
                free_fcn = "oe_free_ocall_buffer";
                call = "oe_call_host_function";
            }
            else
            {
                alloc_fcn = "oe_malloc";
                free_fcn = "oe_free";
                call = "oe_call_enclave_function";
            }
        }
    }

    void adjust_size_deep_copy(
    const std::string& parent_condition,
    const std::string& parent_expr,
    const std::string& buffer_size,
    Decl* parent_prop,
    int level,
    std::string indent = "    ", bool _is_popsgx = false,
    const std::string& parent_type = "")
    {
        UserType* ut = get_user_type_for_deep_copy(edl_, parent_prop);
        if (!ut)
            return;
        iterate_deep_copyable_fields(ut, [&](Decl* prop) {
            std::string op = *parent_expr.rbegin() == ']' ? "." : "->";
            std::string expr = parent_expr + op + prop->name_;
            std::string prefix = "_args." + parent_expr + op;
            
            if(_is_popsgx)
                prefix = "t_" + parent_expr + op;

            std::string argcount = pcount(prop, prefix);
            std::string argsize = psize(prop, prefix);
            std::string argtype = ptype(prop, "_pargs->");
            std::string cond = "_pargs_in->" + parent_condition + " && " + "_pargs_in->" + expr;
            out() << indent + "if (" + cond + "){";

            if(_is_popsgx){
                out() << indent + "    " + "_pargs_in->" + expr +
                        " = " + parent_type + "(_buffer + (size_t)" + "_pargs_in->" + expr + ");";
            }else{
                out() << indent + "    //Nothing present";
            }
            
            out() << indent + "}";

            UserType* ut = get_user_type_for_deep_copy(edl_, prop);
            if (!ut)
                return;

            std::string count = count_attr_str(prop->attrs_->count_, prefix);

            if (count == "1" || count == "")
            {
                adjust_size_deep_copy(
                    cond, expr, buffer_size, prop, level + 1, indent, _is_popsgx);
            }
            else
            {
                std::string idx = "_i_" + to_str(level);
                std::string expr =
                    parent_expr + op + prop->name_ + "[" + idx + "]";
                out() << indent + "for (size_t " + idx + " = 0; " + idx +
                             " < " + count + "; " + idx + "++)"
                      << indent + "{";
                adjust_size_deep_copy(
                    cond, expr, buffer_size, prop, level + 1, indent + "    ", _is_popsgx);
                out() << indent + "}";
            }
        });
    }

    void adjust_buffer_inputs(Function* f)
    {
      bool empty = true;
      out() <<"    /* Setup input arg struct pointer. */"
            <<"    _pargs_in = (" + f->name_ + "_args_t*)_input_buffer;"
            <<""
            <<"    /* Adjust the pointers within _pargs_in */";
      for(Decl* p : f->params_)
      {
        std::string mt = mtype_str(p);
        if (p->attrs_ && (p->attrs_->in_ || p->attrs_->inout_))
        {
            empty = false;
            out() << "    if (_pargs_in->" + p->name_ + ")"
                  << "        _pargs_in->" + p->name_ + " = (" + mt +")(_buffer + (size_t)_pargs_in->" + p->name_ +");";
        }

        /* Skip the nested pointers if the parameter is not
         * deep-copyable or has the out-only attribute. */
        UserType* ut = get_user_type_for_deep_copy(edl_, p);
        if (!ut || (p->attrs_->out_ && !p->attrs_->inout_))
            continue;        
        std::string count = count_attr_str(p->attrs_->count_, "_args.");         
        if (count == "1" || count == ""){
                std::string cond = p->name_;
                std::string expr = p->name_;
                adjust_size_deep_copy(cond, expr, "", p, 2, "    ", true);
        }else{
                std::string cond = p->name_;
                std::string expr = p->name_ + "[_i_1]";
                out() << "    for (size_t _i_1 = 0; _i_1 < " + count +
                             "; _i_1++)"
                      << "    {";
                adjust_size_deep_copy(cond, expr, "", p, 2, "        ", true);
                out() << "    }";
        }
      }
      if(empty)
          out() << "    /* There were no in nor in-out parameters. */";
      out()<<"";
    }

    void adjust_buffer_outputs(Function* f)
    {
        out() << ""
              <<"    /* Setup output arg struct pointer. */"
              <<"    _pargs_out = (" + f->name_ + "_args_t*)_output_buffer;";
    }

    void emit(Function* f, bool ecall, const std::string& prefix = "popsgx")
    {
      ecall_ = ecall;
      has_deep_copy_out_ = has_deep_copy_out(edl_, f);
      std::string alloc_fcn;
      std::string free_fcn;
      std::string call;
      get_functions(f, alloc_fcn, free_fcn, call);
      std::string other = ecall ? "enclave" : "host";
      std::string fcn_id = edl_->name_ + "_fcn_id_" + f->name_;

      std::string args_t = f->name_ + "_args_t";

      /*
         * To avoid duplicated definitions of the ecall wrapper on the host
         * side, the ecall wrapper is defined as [edl_name]_[prefix]_[fun_name].
         * Then we use weak_alias([edl_name]_[prefix]_[fun_name],
         * [prefix]_[fun_name]) to make the exposed [prefix]_[fun_name] weak.
         * Therefore, only one of the implementations will be picked by the
         * linker.
         */
        std::string _prefix = "popsgx_";

        out() <<""
              <<"oe_result_t " + _prefix + f->name_ +  "(oe_enclave_t* enclave){"
              <<"    oe_result_t _result = OE_FAILURE;"
              <<"    static uint64_t global_id = OE_GLOBAL_ECALL_ID_NULL;"
              <<""
              <<"    /* Marshalling struct. */"
              <<"    " + args_t + " _args, *_pargs_in = NULL, *_pargs_out = NULL;"
              <<"    size_t _input_buffer_size = 0;"
              <<"    size_t _output_buffer_size = 0;"
              <<"    size_t _total_buffer_size = 0;"
              <<"    uint8_t* _buffer = NULL;"
              <<"    uint8_t* _input_buffer = NULL;"
              <<"    uint8_t* _output_buffer = NULL;"
              <<"    size_t _output_bytes_written = 0;"
              <<"    size_t _output_buffer_offset = 0;"
              <<""
              <<"    ssize_t bytes_sent, bytes_received;"
              <<"    struct timeval t_sstart, t_send, t_nstart, t_nend;"
              <<"";

        if (has_deep_copy_out_)
        {
            out() << "    uint8_t* _deepcopy_out_buffer = NULL;"
                  << "    size_t _deepcopy_out_buffer_size = 0;"
                  << "    size_t _deepcopy_out_buffer_offset = 0;";
        }

        out() <<""
              <<"    /* Return value from ecall*/"
              <<"    int _retval;"
              <<"    size_t _popsgx_buffer_sizes[3] = {0};"
              <<""
              <<"    //gettimeofday(&t_nstart, NULL);"
              <<"    bytes_received = popsgx_read(connfd, _popsgx_buffer_sizes, sizeof(_popsgx_buffer_sizes));"
              <<"    if(bytes_received != sizeof(_popsgx_buffer_sizes)){"
              <<"        close(connfd);"
              <<"        return OE_FAILURE;"
              <<"    }"
              <<""
              <<"    _input_buffer_size = _popsgx_buffer_sizes[0];"
              <<"    _output_buffer_size = _popsgx_buffer_sizes[1];"
              <<"    _total_buffer_size = _popsgx_buffer_sizes[2];"
              <<""
              <<"    _buffer = (uint8_t*)oe_malloc(_total_buffer_size);"
              <<""
              <<"    bytes_received = popsgx_read(connfd, _buffer, _total_buffer_size);"
              <<"    if(bytes_received != _total_buffer_size){"
              <<"        close(connfd);"
              <<"        return OE_FAILURE;"
              <<"    }"
              <<""
              <<"    //gettimeofday(&t_nend, NULL);"
              <<"    //network_time += (t_nend.tv_sec - t_nstart.tv_sec) * 1e6 + (t_nend.tv_usec - t_nstart.tv_usec);"
              <<""
              <<"    gettimeofday(&t_sstart, NULL);"
              <<"    _input_buffer = _buffer;"
              <<"    _output_buffer = _buffer + _input_buffer_size;"
              <<"";
        adjust_buffer_inputs(f);
        adjust_buffer_outputs(f);
        out() << ""
              << "    /* Call " + other + " function. */"
              << "    _result = " + call + "(";
        if(!gen_t())
        {
             out() << "             enclave,"
                   << "             &global_id,"
                   << "             _" + edl_->name_ + "_ecall_info_table[" +
                       fcn_id + "].name,";
        }
        else
        {
             out() << "             " + fcn_id + ",";
        }
        out() << "             _input_buffer,"
              << "             _input_buffer_size,"
              << "             _output_buffer,"
              << "             _output_buffer_size,"
              << "             &_output_bytes_written);"
              << "";
        out() << "    //gettimeofday(&t_nstart, NULL);"
              << "    gettimeofday(&t_send, NULL);"
              << "    ser_des_time += (t_send.tv_sec - t_sstart.tv_sec) * 1e6 + (t_send.tv_usec - t_sstart.tv_usec);"
              << "    bytes_sent = popsgx_send(connfd, _buffer, _total_buffer_size);"
              << "    if (bytes_sent != _total_buffer_size) {"
              << "        close(connfd);"
              << "        return OE_FAILURE;"
              << "    }"
              << ""
              << "    bytes_sent = popsgx_send(connfd, &_output_bytes_written, sizeof(size_t));"
              << "    if(bytes_sent != sizeof(size_t)){"
              << "        close(connfd);"
              << "        return OE_FAILURE;"
              << "    }"
              << "    //gettimeofday(&t_nend, NULL);"
              << "    //network_time += (t_nend.tv_sec - t_nstart.tv_sec) * 1e6 + (t_nend.tv_usec - t_nstart.tv_usec);"
              << "    printf(\"Network time taken: %ld microseconds\\n\", network_time);"
              << "    printf(\"Serial time taken: %ld microseconds\\n\", ser_des_time);"
              << "";

        if (has_deep_copy_out_ && !gen_t())
        {
                    out() 
                    << ""
                    << "    bytes_sent = popsgx_send(connfd, &_pargs_out->deepcopy_out_buffer_size, sizeof(size_t));"
                    << "    if (bytes_sent != sizeof(size_t)){"
                    << "        close(connfd);"
                    << "        return OE_FAILURE;"
                    << "    }"
                    << ""
                    << "    bytes_sent = popsgx_send(connfd, _pargs_out->deepcopy_out_buffer, _pargs_out->deepcopy_out_buffer_size);"
                    << "    if (bytes_sent != _pargs_out->deepcopy_out_buffer_size){"
                    << "        close(connfd);"
                    << "        return OE_FAILURE;"
                    << "    }"
                    << "";
        }

        out() << ""
              << "done:"
              << "    if(_buffer)"
              << "        oe_free(_buffer);"
              << ""
              << "    return _result;"
              << "}"
              << "";
    }
};

#endif //POP_W_EMITTER_H1