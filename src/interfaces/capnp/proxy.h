#ifndef BITCOIN_INTERFACES_CAPNP_PROXY_H
#define BITCOIN_INTERFACES_CAPNP_PROXY_H

#include <interfaces/base.h>
#include <interfaces/capnp/util.h>
#include <util.h>
#include <interfaces/capnp/proxy.capnp.h>

#include <capnp/blob.h> // for capnp::Text
#include <capnp/common.h>
#include <functional>
#include <kj/async.h>
#include <list>
#include <memory>

// FIXME Rename Impl->Class everywhere

namespace interfaces {
namespace capnp {

class EventLoop;

using CleanupList = std::list<std::function<void()>>;
using CleanupIt = typename CleanupList::iterator;

//! Mapping from capnp interface type to proxy client implementation (specializations are generated by
//! proxy-codegen.cpp).
template <typename Interface>
struct ProxyClient;

//! Mapping from capnp interface type to proxy server implementation (specializations are generated by
//! proxy-codegen.cpp).
template <typename Interface>
struct ProxyServer;

//! Mapping from capnp method params type to method traits (specializations are generated by proxy-codegen.cpp).
template <typename Params>
struct ProxyMethod;

//! Mapping from capnp struct type to struct traits (specializations are generated by proxy-codegen.cpp).
template <typename Struct>
struct ProxyStruct;

//! Mapping from local c++ type to capnp type and traits (specializations are generated by proxy-codegen.cpp).
template <typename Type>
struct ProxyType;

//! Compile time representation of RPC field annotation.
template <uint64_t id>
using ProxyAnnotation = std::integral_constant<uint64_t, id>;

struct ThreadContext;
extern thread_local ThreadContext g_thread_context;

struct InvokeContext
{
    EventLoop& loop;
};

//! Wrapper around std::function for passing std::function objects between client and servers.
// FIXME: Get rid of specialization, just make this take straight <Result, Args> template params.
template <typename Fn>
class ProxyCallback;

template <typename Result, typename... Args>
class ProxyCallback<std::function<Result(Args...)>> : public Base
{
public:
    virtual Result call(Args&&... args) = 0;
};

//! Get return type of a callable type.
template <typename Callable>
using ResultOf = decltype(std::declval<Callable>()());

//! Wrapper around callback function for compatibility with std::async.
//!
//! std::async requires callbacks to be copyable and requires noexcept
//! destructors, but this doesn't work well with kj types which are generally
//! move-only and not noexcept.
template <typename Callable>
struct AsyncCallable
{
    AsyncCallable(Callable&& callable) : m_callable(std::make_shared<Callable>(std::move(callable))) {}
    AsyncCallable(const AsyncCallable&) = default;
    AsyncCallable(AsyncCallable&&) = default;
    ~AsyncCallable() noexcept {}
    ResultOf<Callable> operator()() const { return (*m_callable)(); }
    mutable std::shared_ptr<Callable> m_callable;
};

//! Construct AsyncCallable object.
template <typename Callable>
AsyncCallable<typename std::remove_reference<Callable>::type> MakeAsyncCallable(Callable&& callable)
{
    return std::move(callable);
}

// FIXME: Move to -impl.h
template <typename Result, typename... Args>
class ProxyCallbackImpl : public ProxyCallback<std::function<Result(Args...)>>
{
    using Fn = std::function<Result(Args...)>;
    Fn m_fn;

public:
    ProxyCallbackImpl(Fn fn) : m_fn(std::move(fn)) {}
    Result call(Args&&... args) override { return m_fn(std::forward<Args>(args)...); }
};

template <typename Interface_, typename Class_>
class ProxyClientBase : public Class_
{
public:
    using Interface = Interface_;
    using Class = Class_;

    ProxyClientBase(typename Interface::Client client, EventLoop& loop);
    ~ProxyClientBase() noexcept;

    // Methods called during client construction/destruction that can optionally
    // be defined in capnp interface to trigger the server.
    void construct() {}
    void destroy() {}

    ProxyClient<Interface>& self() { return static_cast<ProxyClient<Interface>&>(*this); }

    typename Interface::Client m_client;
    EventLoop* m_loop;
    CleanupIt m_cleanup;
};

template <typename MethodTraits, typename GetRequest, typename ProxyClient, typename... _Params>
void clientInvoke(MethodTraits, const GetRequest& get_request, ProxyClient& proxy_client, _Params&&... params);

template <typename Interface_, typename Class_>
class ProxyServerBase : public virtual Interface_::Server
{
public:
    using Interface = Interface_;
    using Class = Class_;

    ProxyServerBase(Class* impl, bool owned, EventLoop& loop) : m_impl(impl), m_owned(owned), m_loop(&loop) {}
    ~ProxyServerBase() { invokeDestroy(false /* remote */); }

    void invokeDestroy(bool remote)
    {
        if (m_owned) {
            delete m_impl;
            m_impl = nullptr;
            m_owned = false;
        }
    }

    Class* m_impl;
    /**
     * Whether or not to delete native interface pointer when this capnp server
     * goes out of scope. This is true for servers created to wrap
     * unique_ptr<Impl> method arguments, but false for servers created to wrap
     * Impl& method arguments.
     *
     * In the case of Impl& arguments, custom code is required on other side of
     * the connection to delete the capnp client & server objects since native
     * code on that side of the connection will just be taking a plain reference
     * rather than a pointer, so won't be able to do its own cleanup. Right now
     * this is implemented with addCloseHook callbacks to delete clients at
     * appropriate times depending on semantics of the particular method being
     * wrapped. */
    bool m_owned;
    EventLoop* m_loop;
};

template <typename Interface, typename Class>
class ProxyServerCustom : public ProxyServerBase<Interface, Class>
{
    using ProxyServerBase<Interface, Class>::ProxyServerBase;
};

template <typename Interface, typename Class>
class ProxyClientCustom : public ProxyClientBase<Interface, Class>
{
    using ProxyClientBase<Interface, Class>::ProxyClientBase;
};

//! Function traits class.
// FIXME Get rid of Fields logic, should be consolidated and moved to implementation
// FIXME get rid of underscores
template <class Fn>
struct FunctionTraits;

template <class _Class, class _Result, class... _Params>
struct FunctionTraits<_Result (_Class::*const)(_Params...)>
{
    using Params = TypeList<_Params...>;
    using Result = _Result;
    template <size_t N>
    using Param = typename std::tuple_element<N, std::tuple<_Params...>>::type;
    using Fields =
        typename std::conditional<std::is_same<void, Result>::value, Params, TypeList<_Params..., _Result>>::type;
};

template <class _Class, class _Result, class... _Params>
struct FunctionTraits<_Result (_Class::*)(_Params...)>
{
    using Result = _Result;
};

template <class _Class, class _Result, class... _Params>
struct FunctionTraits<_Result (_Class::*)(_Params...) const>
{
    using Result = _Result;
};

template <>
struct FunctionTraits<std::nullptr_t>
{
    using Result = std::nullptr_t;
};

template <typename Method, typename Enable = void>
struct ProxyMethodTraits
{
    using Params = TypeList<>;
    using Result = void;
    using Fields = Params;

    template <typename Class>
    static void invoke(Class& impl)
    {
    }
};

template <typename Method>
struct ProxyMethodTraits<Method, typename std::enable_if<true || ProxyMethod<Method>::impl>::type>
    : public FunctionTraits<decltype(ProxyMethod<Method>::impl)>
{
    template <typename ServerContext, typename... Args>
    static auto invoke(ServerContext& server_context, Args&&... args)
        -> AUTO_RETURN((server_context.proxy_server.m_impl->*ProxyMethod<Method>::impl)(std::forward<Args>(args)...))
};

template <typename Method>
struct ProxyClientMethodTraits : public ProxyMethodTraits<Method>
{
};
template <typename Method>
struct ProxyServerMethodTraits : public ProxyMethodTraits<Method>
{
};


template <typename ProxyServer, typename CallContext_>
struct ServerInvokeContext : InvokeContext
{
    using CallContext = CallContext_;

    ProxyServer& proxy_server;
    CallContext& call_context;
    int req;

    ServerInvokeContext(ProxyServer& proxy_server, CallContext& call_context, int req)
        : InvokeContext{*proxy_server.m_loop}, proxy_server{proxy_server}, call_context{call_context}, req{req}
    {
    }
};

template <typename Interface, typename Params, typename Results>
using ServerContext = ServerInvokeContext<ProxyServer<Interface>, ::capnp::CallContext<Params, Results>>;

// Create or update field value using reader.
// template <typename ParamTypes, typename Reader, typename... Values>
// void ReadField(LocalTypes, InvokeContext& invoke_context, Reader&& reader, Values&&... values);

// Read field value using reader, then call fn(fn_params..., field_value_params...),
// then update field value using builder. Skip updating field value if argument
// is input-only, and skip reading field value if argument is output-only.
// template <typename CapTypes, typename ParamTypes, typename Reader, typename Builder, typename Fn, typename...
// FnParams>
// booln bbsField(CapTypes, ParamTypes, InvokeContext& invoke_context, Input&& input, Output&& output, Fn&& fn,
// FnParams&&... fn_params);

template <typename CapValue, typename Enable = void>
struct CapValueTraits
{
    using CapType = CapValue;
};

template <typename CapValue>
struct CapValueTraits<CapValue, Require<typename CapValue::Reads>>
{
    using CapType = typename CapValue::Reads;
};

template <typename CapValue>
struct CapValueTraits<CapValue, Require<typename CapValue::Builds>>
{
    using CapType = typename CapValue::Builds;
};

template <>
struct CapValueTraits<::capnp::Text::Builder, void>
{
    // Workaround for missing Builds typedef in capnp 0.?? FIXME
    using CapType = ::capnp::Text;
};

template <typename Value>
class ValueField
{
public:
    ValueField(Value& value) : m_value(value) {}
    ValueField(Value&& value) : m_value(value) {}
    Value& m_value;

    Value& get() { return m_value; }
    Value& init() { return m_value; }
    bool has() { return true; }
};

// FIXME: Move to impl.h after buildfield priority arguments removed
template <int priority>
struct Priority : Priority<priority - 1>
{
};

template <>
struct Priority<0>
{
};

using BuildFieldPriority = Priority<3>;

// FIXME: probably move to impl.h after buildfield revamp
template <typename Setter, typename Enable = void>
struct CapSetterMethodTraits;

template <typename Builder, typename FieldType>
struct CapSetterMethodTraits<FieldType (Builder::*)(), void> : CapValueTraits<FieldType>
{
};

template <typename Builder, typename FieldType>
struct CapSetterMethodTraits<FieldType (Builder::*)(unsigned int),
    typename std::enable_if<!std::is_same<FieldType, void>::value>::type> : CapValueTraits<FieldType>
{
};

template <typename Builder, typename FieldType>
struct CapSetterMethodTraits<void (Builder::*)(FieldType), void> : CapValueTraits<Decay<FieldType>>
{
};

template <>
struct CapSetterMethodTraits<std::nullptr_t, void>
{
};

//! Call method given method pointer and object.
// FIXME Try to get rid of callmethod entirely by detecting nullptr_t setting in StructField, other places
template <typename Result = void,
    typename Class,
    typename MethodResult,
    typename MethodClass,
    typename... MethodParams,
    typename... Params>
MethodResult CallMethod(Class& object, MethodResult (MethodClass::*method)(MethodParams...), Params&&... params)
{
    return (object.*method)(std::forward<Params>(params)...);
}

template <typename Result = void,
    typename Class,
    typename MethodResult,
    typename MethodClass,
    typename... MethodParams,
    typename... Params>
MethodResult CallMethod(Class& object, MethodResult (MethodClass::*method)(MethodParams...) const, Params&&... params)
{
    return (object.*method)(std::forward<Params>(params)...);
}

template <typename Result, typename Class, typename... Params>
Result CallMethod(Class&, std::nullptr_t, Params&&...)
{
    return Result();
}

template <typename Accessor, typename Struct>
struct StructField
{
    template <typename S>
    StructField(S& struct_) : m_struct(struct_)
    {
    }
    Struct& m_struct;

    template<typename A = Accessor> auto get() const -> AUTO_RETURN(A::get(this->m_struct))
    template<typename A = Accessor> auto has() const -> typename std::enable_if<A::optional, bool>::type { return A::getHas(m_struct); }
    template<typename A = Accessor> auto has() const -> typename std::enable_if<!A::optional && A::boxed, bool>::type { return A::has(m_struct); }
    template<typename A = Accessor> auto has() const -> typename std::enable_if<!A::optional && !A::boxed, bool>::type { return true; }
    template<typename A = Accessor> auto want() const -> typename std::enable_if<A::requested, bool>::type { return A::getWant(m_struct); }
    template<typename A = Accessor> auto want() const -> typename std::enable_if<!A::requested, bool>::type { return true; }

    template<typename A = Accessor, typename... Args> auto set(Args&&... args) const -> AUTO_RETURN(A::set(this->m_struct, std::forward<Args>(args)...))
    template<typename A = Accessor, typename... Args> auto init(Args&&... args) const -> AUTO_RETURN(A::init(this->m_struct, std::forward<Args>(args)...))
    template<typename A = Accessor> auto setHas() const -> typename std::enable_if<A::optional>::type { return A::setHas(m_struct); }
    template<typename A = Accessor> auto setHas() const -> typename std::enable_if<!A::optional>::type { }
    template<typename A = Accessor> auto setWant() const -> typename std::enable_if<A::requested>::type { return A::setWant(m_struct); }
    template<typename A = Accessor> auto setWant() const -> typename std::enable_if<!A::requested>::type { }
};

template <typename CapType, ::capnp::Kind = ::capnp::kind<CapType>()>
struct CapTypeTraits
{
    template <typename Class>
    using Setter = void (Class::*)(CapType);
};

template <typename CapType>
struct CapTypeTraits<CapType, ::capnp::Kind::BLOB>
{
    template <typename Class>
    using Setter = ::capnp::BuilderFor<CapType> (Class::*)(unsigned);
};

template <typename CapType>
struct CapTypeTraits<CapType, ::capnp::Kind::LIST>
{
    template <typename Class>
    using Setter = ::capnp::BuilderFor<CapType> (Class::*)(unsigned);
};

template <typename CapType>
struct CapTypeTraits<CapType, ::capnp::Kind::STRUCT>
{
    template <typename Class>
    using Setter = ::capnp::BuilderFor<CapType> (Class::*)();
};

// FIXME: probably move to impl.h after buildfield revamp
// Adapter to let BuildField overloads methods work set & init list elements as
// if they were fields of a struct. If BuildField is changed to use some kind of
// accessor class instead of calling method pointers, then then maybe this could
// go away or be simplified, because would no longer be a need to return
// ListOutput method pointers emulating capnp struct method pointers..
template <typename ListType>
struct ListOutput;

template <typename T, ::capnp::Kind kind>
struct ListOutput<::capnp::List<T, kind>>
{
    using Builder = typename ::capnp::List<T, kind>::Builder;

    ListOutput(Builder& builder, size_t index) : m_builder(builder), m_index(index) {}
    Builder& m_builder;
    size_t m_index;

    auto get() const -> AUTO_RETURN(this->m_builder[this->m_index])
    auto init() const -> AUTO_RETURN(this->m_builder[this->m_index])
    template<typename B = Builder, typename Arg> auto set(Arg&& arg) const -> AUTO_RETURN(this->m_builder.B::set(m_index, std::forward<Arg>(arg)))
    template<typename B = Builder, typename Arg> auto init(Arg&& arg) const -> AUTO_RETURN(this->m_builder.B::init(m_index, std::forward<Arg>(arg)))
};

static constexpr int FIELD_IN = 1;
static constexpr int FIELD_OUT = 2;
static constexpr int FIELD_OPTIONAL = 4;
static constexpr int FIELD_REQUESTED = 8;
static constexpr int FIELD_BOXED = 16;

template <typename Field, int flags>
struct Accessor : public Field
{
    static const bool in = flags & FIELD_IN;
    static const bool out = flags & FIELD_OUT;
    static const bool optional = flags & FIELD_OPTIONAL;
    static const bool requested = flags & FIELD_REQUESTED;
    static const bool boxed = flags & FIELD_BOXED;
};

template <>
class ProxyServer<ThreadMap> : public virtual ThreadMap::Server
{
public:
    ProxyServer(EventLoop& loop);
    kj::Promise<void> makeThread(MakeThreadContext context) override;
    EventLoop& m_loop;
};


std::string LongThreadName(const char* exe_name);

#define LogIpc(loop, format, ...)                                       \
    LogPrint(::BCLog::IPC, "{%s} " format, LongThreadName((loop).m_exe_name), ##__VA_ARGS__)

} // namespace capnp
} // namespace interfaces

#endif // BITCOIN_INTERFACES_CAPNP_PROXY_H
