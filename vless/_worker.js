import { connect as 连接 } from "cloudflare:sockets";
let UUID = "00000000-0000-0000-0000-000000000000";
let PROXYIP = "";
let UUID字节;
function 更新UUID字节(){
  const 十六进制 = UUID.replace(/-/g, "");
  UUID字节 = new Uint8Array(16);

  for(let 索引=0;索引<16;索引++){
    UUID字节[索引]=parseInt(
      十六进制.slice(索引*2,索引*2+2),
      16
    );
  }
}
function UUID相等(甲,乙){
  if(甲.length!==16||乙.length!==16){
    return false;
  }
  let 差异=0;
  for(let 索引=0;索引<16;索引++){
    差异|=甲[索引]^乙[索引];
  }
  return 差异===0;
}
function 解析代理IP(数值){
  数值=String(数值||"").trim();
  if(数值.startsWith("[")){
    const 结束位置=数值.indexOf("]");
    return {
      hostname:数值.slice(1,结束位置),
      port:Number(数值.slice(结束位置+2))||443
    };
  }
  const 冒号数量=(数值.match(/:/g)||[]).length;
  if(冒号数量>1){
    return {
      hostname:数值,
      port:443
    };
  }
  const 最后冒号=数值.lastIndexOf(":");
  if(最后冒号>0){
    return {
      hostname:数值.slice(0,最后冒号),
      port:Number(数值.slice(最后冒号+1))||443
    };
  }
  return {
    hostname:数值,
    port:443
  };
}
function 获取自定义代理IP(路径){
  if(!路径.startsWith("/pyip=")){
    return "";
  }
  return decodeURIComponent(路径.slice(6)).trim();
}
function 转换八位数组(数据){
  if(数据 instanceof ArrayBuffer){
    return new Uint8Array(数据);
  }
  if(ArrayBuffer.isView(数据)){
    return new Uint8Array(
      数据.buffer,
      数据.byteOffset,
      数据.byteLength
    );
  }
  return null;
}
async function 获取网套数据(数据){
  if(数据 instanceof Blob){
    return new Uint8Array(await 数据.arrayBuffer());
  }
  const 字节数据=转换八位数组(数据);
  if(字节数据){
    return 字节数据;
  }
  if(typeof 数据==="string"){
    return new TextEncoder().encode(数据);
  }
}
function 解析微列死(缓冲区){
  const 数据=new Uint8Array(缓冲区);
  if(!UUID相等(数据.subarray(1,17),UUID字节)){
    throw new Error("UUID错误");
    }
  const 版本=数据[0];
  const 附加长度=数据[17];
  let 偏移=18+附加长度;
  const 命令=数据[偏移++];
  const 端口=(数据[偏移]<<8)|数据[偏移+1];
  偏移+=2;
  const 地址类型=数据[偏移++];
  let 主机;
  if(地址类型===1){
    主机=Array.from(
      数据.subarray(偏移,偏移+4)
    ).join(".");
    偏移+=4;
  }else if(地址类型===2){
    const 长度=数据[偏移++];
    主机=new TextDecoder().decode(
      数据.subarray(偏移,偏移+长度)
    );
    偏移+=长度;
  }else if(地址类型===3){
    const 地址部分=[];
    for(let 索引=0;索引<16;索引+=2){
      地址部分.push(
        (
          (数据[偏移+索引]<<8)|
          数据[偏移+索引+1]
        ).toString(16)
      );
    }
    主机=地址部分.join(":");
    偏移+=16;
  }
  return {
    版本,
    主机,
    端口,
    载荷:数据.subarray(偏移)
  };
}
async function 创建套接字(主机,端口){
  const 套接字=连接(
    {
      hostname:主机.includes(":")
        ?`[${主机}]`
        :主机,
      port:端口
    },
    {
      allowHalfOpen:true
    }
  );
  await 套接字.opened;
  return 套接字;
}
async function 关闭套接字(套接字){
  if(!套接字){
    return;
  }
  try{
    await 套接字.close();
  }catch{}
}
async function 处理网套请求(请求){
  const 网址对象=new URL(请求.url);
  const 自定义代理地址=获取自定义代理IP(网址对象.pathname);
  let 代理地址=自定义代理地址||PROXYIP;
  if(!代理地址){
  try{
    const 响应=await fetch("https://api.ipapi.is");
    const 信息=await 响应.json();
    代理地址=信息.ip;
     }catch{}
    }
  const 代理=解析代理IP(代理地址);
  const 网套组=new WebSocketPair();
  const 客户端=网套组[0];
  const 服务端=网套组[1];
  服务端.accept({
    allowHalfOpen:true
  });
  const 状态={
    已关闭:false,
    已初始化:false,
    已发送响应:false,
    正在连接:false,
    套接字:null,
    读取器:null,
    写入器:null,
    等待队列:[],
    写入链:Promise.resolve()
  };
  const 全部关闭=async()=>{
    if(状态.已关闭){
      return;
    }
    状态.已关闭=true;
    状态.等待队列.length=0;
    try{
      状态.读取器?.cancel();
    }catch{}
    try{
      状态.读取器?.releaseLock();
    }catch{}
    try{
      状态.写入器?.releaseLock();
    }catch{}
    await 关闭套接字(状态.套接字);
    状态.读取器=null;
    状态.写入器=null;
    状态.套接字=null;
    try{
      服务端.close();
    }catch{}
  };
  const 发送响应=(版本)=>{
    if(状态.已发送响应){
      return;
    }
    状态.已发送响应=true;
    服务端.send(
      new Uint8Array([
        版本,
        0
      ])
    );
  };
  const 写入上游=(数据)=>{
    if(!数据||!数据.byteLength){
      return 状态.写入链;
    }
    状态.写入链=状态.写入链.then(async()=>{
      if(!状态.写入器){
        状态.等待队列.push(
          new Uint8Array(
            数据.slice(0)
          )
        );
        return;
      }
      await 状态.写入器.write(数据);
    });
    return 状态.写入链;
  };
  const 清空等待队列=async()=>{
    if(!状态.写入器){
      return;
    }
    while(
      状态.等待队列.length&&
      !状态.已关闭
    ){
      const 数据块=状态.等待队列.shift();
      await 状态.写入器.write(数据块);
    }
  };
  const 启动读取=async(套接字,读取器,直连)=>{
    let 已收到数据=false;
    try{
      while(!状态.已关闭){
        const 结果=await 读取器.read();
        if(结果.done){
          if(
            直连&&
            !已收到数据&&
            !状态.已关闭
          ){
            return false;
          }
          return true;
        }
        if(
          结果.value&&
          结果.value.byteLength
        ){
          已收到数据=true;
          服务端.send(结果.value);
        }
      }
      return true;
    }finally{
      try{
        读取器.releaseLock();
      }catch{}
      if(状态.读取器===读取器){
        状态.读取器=null;
      }
    }
  };
    const 连接转发=async(目标)=>{
    let 直连套接字=null;
    try{
      try{
        直连套接字=await 创建套接字(
          目标.主机,
          目标.端口
        );
        if(状态.已关闭){
          await 关闭套接字(直连套接字);
          return;
        }
        状态.套接字=直连套接字;
        状态.写入器=
          直连套接字.writable.getWriter();
        await 清空等待队列();
        const 直连读取器=
          直连套接字.readable.getReader();
        状态.读取器=直连读取器;
        const 直连完成=
          await 启动读取(
            直连套接字,
            直连读取器,
            true
          );
        if(直连完成){
          return;
        }
      }catch{}
      if(状态.已关闭){
        return;
      }
      try{
        状态.读取器?.cancel();
      }catch{}
      try{
        状态.读取器?.releaseLock();
      }catch{}
      try{
        状态.写入器?.releaseLock();
      }catch{}
      状态.读取器=null;
      状态.写入器=null;
      await 关闭套接字(
        状态.套接字
      );
      状态.套接字=null;
      const 代理套接字=
        await 创建套接字(
          代理.hostname,
          代理.port
        );
      if(状态.已关闭){
        await 关闭套接字(
          代理套接字
        );
        return;
      }
      状态.套接字=代理套接字;
      状态.写入器=
        代理套接字.writable.getWriter();
      await 清空等待队列();
      const 代理读取器=
        代理套接字.readable.getReader();
      状态.读取器=代理读取器;
      await 启动读取(
        代理套接字,
        代理读取器,
        false
      );
    }finally{
      try{
        状态.读取器?.cancel();
      }catch{}
      try{
        状态.读取器?.releaseLock();
      }catch{}
      try{
        状态.写入器?.releaseLock();
      }catch{}
      await 关闭套接字(
        状态.套接字
      );
      状态.读取器=null;
      状态.写入器=null;
      状态.套接字=null;
    }
  };
  服务端.addEventListener(
    "message",
    async 事件=>{
      if(状态.已关闭){
        return;
      }
      try{
        const 数据=
          await 获取网套数据(
            事件.data
          );
        if(!数据.byteLength){
          return;
        }
        if(!状态.已初始化){
          const 目标=
            解析微列死(数据);
          状态.已初始化=true;
          发送响应(
            目标.版本
          );
          const 初始载荷=
            目标.载荷;
          if(
            初始载荷&&
            初始载荷.byteLength
          ){
            状态.等待队列.push(
              new Uint8Array(
                初始载荷
              )
            );
          }
          if(!状态.正在连接){
            状态.正在连接=true;
            连接转发(目标)
              .catch(()=>{
                全部关闭();
              });
          }
          return;
        }
        await 写入上游(数据);
      }catch{
        await 全部关闭();
      }
    }
  );
    服务端.addEventListener(
    "close",
    ()=>{
      全部关闭();
    }
  );
  服务端.addEventListener(
    "error",
    ()=>{
      全部关闭();
    }
  );
  return new Response(null,{
    status:101,
    webSocket:客户端
  });
}
export default{
  async fetch(请求,env){
    UUID = env.uuid || UUID;
    PROXYIP = env.pyip || PROXYIP;
    更新UUID字节();
    const 网址对象=new URL(请求.url);
    const 路径=
      decodeURIComponent(
        网址对象.pathname
      );
    const 升级=
      请求.headers.get("Upgrade");
    const 是否网套=
      升级&&
      升级.toLowerCase()==="websocket";
    if(
      是否网套&&
      (
        路径===" /".trim()||
        路径.startsWith("/pyip=")
      )
    ){
      return 处理网套请求(请求);
    }
    if(路径===`/${UUID}`||路径===`/${UUID}/`){
      return new Response("OK");
    }
    return fetch("https://www.cctv.com");
  }
};
