import { connect as 连接 } from "cloudflare:sockets";

let PASSWORD = "admin";
let PROXYIP = "";

const 密钥长度 = 16;
const 盐长度 = 16;
const 随机数长度 = 12;
const 标签长度 = 16;
function MD5(数据) {
  function 循环左移(值, 位数) {
    return (值 << 位数) | (值 >>> (32 - 位数));
  }
  function 添加到块(字节数组) {
    const 长度 = 字节数组.length;
    const 位长度 = 长度 * 8;
    const 块数 = ((长度 + 8) >>> 6) + 1;
    const 块 = new Array(块数 * 16).fill(0);
    for (let i = 0; i < 长度; i++) {
      块[i >> 2] |= 字节数组[i] << ((i % 4) * 8);
    }
    块[长度 >> 2] |= 0x80 << ((长度 % 4) * 8);
    块[块数 * 16 - 2] = 位长度;
    return 块;
  }
  const 原始 = 数据 instanceof Uint8Array ? 数据 : new TextEncoder().encode(数据);
  const 块 = 添加到块(原始);
  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  const S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
  const K = new Uint32Array(64);
  for (let i = 0; i < 64; i++) {
    K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) >>> 0;
  }
  for (let i = 0; i < 块.length; i += 16) {
    let A = a0, B = b0, C = c0, D = d0;
    for (let j = 0; j < 64; j++) {
      let F, g;
      if (j < 16) {
        F = (B & C) | (~B & D);
        g = j;
      } else if (j < 32) {
        F = (D & B) | (~D & C);
        g = (5 * j + 1) % 16;
      } else if (j < 48) {
        F = B ^ C ^ D;
        g = (3 * j + 5) % 16;
      } else {
        F = C ^ (B | ~D);
        g = (7 * j) % 16;
      }
      F = (F + A + K[j] + 块[i + g]) >>> 0;
      A = D;
      D = C;
      C = B;
      B = (B + 循环左移(F, S[j])) >>> 0;
    }
    a0 = (a0 + A) >>> 0;
    b0 = (b0 + B) >>> 0;
    c0 = (c0 + C) >>> 0;
    d0 = (d0 + D) >>> 0;
  }
  const 结果 = new Uint8Array(16);
  const 视图 = new DataView(结果.buffer);
  视图.setUint32(0, a0, true);
  视图.setUint32(4, b0, true);
  视图.setUint32(8, c0, true);
  视图.setUint32(12, d0, true);
  return 结果;
}
function 派生主密钥(密码) {
  const 密码字节 = new TextEncoder().encode(密码);
  let 密钥 = new Uint8Array(密钥长度);
  let 偏移 = 0;
  let 上一次 = new Uint8Array(0);
  while (偏移 < 密钥长度) {
    const 输入 = new Uint8Array(上一次.length + 密码字节.length);
    输入.set(上一次);
    输入.set(密码字节, 上一次.length);
    上一次 = MD5(输入);
    const 拷贝长度 = Math.min(上一次.length, 密钥长度 - 偏移);
    密钥.set(上一次.subarray(0, 拷贝长度), 偏移);
    偏移 += 拷贝长度;
  }
  return 密钥;
}
async function 派生子密钥(主密钥, 盐) {
  const 基础密钥 = await crypto.subtle.importKey("raw", 主密钥, { name: "HKDF" }, false, ["deriveBits"]);
  const 位 = await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-1", salt: 盐, info: new TextEncoder().encode("ss-subkey") }, 基础密钥, 密钥长度 * 8);
  return new Uint8Array(位);
}
function 增加随机数(随机数) {
  for (let i = 0; i < 随机数.length; i++) {
    随机数[i]++;
    if (随机数[i] !== 0) {
      break;
    }
  }
}
async function 加密(密钥, 随机数, 明文) {
  const 密钥对象 = await crypto.subtle.importKey("raw", 密钥, { name: "AES-GCM" }, false, ["encrypt"]);
  const 密文 = await crypto.subtle.encrypt({ name: "AES-GCM", iv: 随机数, tagLength: 128 }, 密钥对象, 明文);
  return new Uint8Array(密文);
}
async function 解密(密钥, 随机数, 密文) {
  const 密钥对象 = await crypto.subtle.importKey("raw", 密钥, { name: "AES-GCM" }, false, ["decrypt"]);
  const 明文 = await crypto.subtle.decrypt({ name: "AES-GCM", iv: 随机数, tagLength: 128 }, 密钥对象, 密文);
  return new Uint8Array(明文);
}
function 解析代理IP(数值) {
  数值 = String(数值 || "").trim();
  if (数值.startsWith("[")) {
    const 结束位置 = 数值.indexOf("]");
    return {
      hostname: 数值.slice(1, 结束位置),
      port: Number(数值.slice(结束位置 + 2)) || 443
    };
  }
  const 冒号数量 = (数值.match(/:/g) || []).length;
  if (冒号数量 > 1) {
    return { hostname: 数值, port: 443 };
  }
  const 最后冒号 = 数值.lastIndexOf(":");
  if (最后冒号 > 0) {
    return {
      hostname: 数值.slice(0, 最后冒号),
      port: Number(数值.slice(最后冒号 + 1)) || 443
    };
  }
  return { hostname: 数值, port: 443 };
}
function 获取自定义代理IP(路径) {
  if (!路径.startsWith("/pyip=")) {
    return "";
  }
  return decodeURIComponent(路径.slice(6)).trim();
}
function 转换八位数组(数据) {
  if (数据 instanceof ArrayBuffer) {
    return new Uint8Array(数据);
  }
  if (ArrayBuffer.isView(数据)) {
    return new Uint8Array(数据.buffer, 数据.byteOffset, 数据.byteLength);
  }
  return null;
}
async function 获取网套数据(数据) {
  if (数据 instanceof Blob) {
    return new Uint8Array(await 数据.arrayBuffer());
  }
  const 字节数据 = 转换八位数组(数据);
  if (字节数据) {
    return 字节数据;
  }
  if (typeof 数据 === "string") {
    return new TextEncoder().encode(数据);
  }
}
function 解析影梭头(缓冲区) {
  const 数据 = new Uint8Array(缓冲区);
  let 偏移 = 0;
  const 地址类型 = 数据[偏移++];
  let 主机;
  if (地址类型 === 1) {
    主机 = Array.from(数据.subarray(偏移, 偏移 + 4)).join(".");
    偏移 += 4;
  } else if (地址类型 === 3) {
    const 长度 = 数据[偏移++];
    主机 = new TextDecoder().decode(数据.subarray(偏移, 偏移 + 长度));
    偏移 += 长度;
  } else if (地址类型 === 4) {
    const 地址部分 = [];
    for (let 索引 = 0; 索引 < 16; 索引 += 2) {
      地址部分.push(((数据[偏移 + 索引] << 8) | 数据[偏移 + 索引 + 1]).toString(16));
    }
    主机 = 地址部分.join(":");
    偏移 += 16;
  } else {
    throw new Error("地址类型错误");
  }
  const 端口 = (数据[偏移] << 8) | 数据[偏移 + 1];
  偏移 += 2;
  return { 主机, 端口, 载荷: 数据.subarray(偏移) };
}
async function 创建套接字(主机, 端口) {
  const 套接字 = 连接({ hostname: 主机.includes(":") ? `[${主机}]` : 主机, port: 端口 }, { allowHalfOpen: true });
  await 套接字.opened;
  return 套接字;
}
async function 关闭套接字(套接字) {
  if (!套接字) {
    return;
  }
  try {
    await 套接字.close();
  } catch {}
}
async function 处理网套请求(请求) {
  const 网址对象 = new URL(请求.url);
  const 自定义代理地址 = 获取自定义代理IP(网址对象.pathname);
  let 代理地址 = 自定义代理地址 || PROXYIP;
  if (!代理地址) {
    try {
      const 响应 = await fetch("https://api.ipapi.is");
      const 信息 = await 响应.json();
      代理地址 = 信息.ip;
    } catch {}
  }
  const 代理 = 解析代理IP(代理地址);
  const 网套组 = new WebSocketPair();
  const 客户端 = 网套组[0];
  const 服务端 = 网套组[1];
  服务端.accept({ allowHalfOpen: true });
  const 主密钥 = 派生主密钥(PASSWORD);
  const 状态 = {
    已关闭: false,
    已初始化: false,
    正在连接: false,
    套接字: null,
    读取器: null,
    写入器: null,
    等待队列: [],
    写入链: Promise.resolve(),
    客户端子密钥: null,
    客户端随机数: null,
    服务端子密钥: null,
    服务端随机数: null,
    已发送服务端盐: false,
    服务端盐: null,
    接收缓冲: new Uint8Array(0),
    已读客户端盐: false
  };
  const 全部关闭 = async () => {
    if (状态.已关闭) {
      return;
    }
    状态.已关闭 = true;
    状态.等待队列.length = 0;
    状态.接收缓冲 = new Uint8Array(0);
    try {
      状态.读取器?.cancel();
    } catch {}
    try {
      状态.读取器?.releaseLock();
    } catch {}
    try {
      状态.写入器?.releaseLock();
    } catch {}
    await 关闭套接字(状态.套接字);
    状态.读取器 = null;
    状态.写入器 = null;
    状态.套接字 = null;
    try {
      服务端.close();
    } catch {}
  };
  const 合并缓冲 = (新数据) => {
    const 合并 = new Uint8Array(状态.接收缓冲.length + 新数据.length);
    合并.set(状态.接收缓冲);
    合并.set(新数据, 状态.接收缓冲.length);
    状态.接收缓冲 = 合并;
  };
  const 消费缓冲 = (长度) => {
    状态.接收缓冲 = 状态.接收缓冲.subarray(长度);
  };
  const 写入上游 = (数据) => {
    if (!数据 || !数据.byteLength) {
      return 状态.写入链;
    }
    状态.写入链 = 状态.写入链.then(async () => {
      if (!状态.写入器) {
        状态.等待队列.push(new Uint8Array(数据.slice(0)));
        return;
      }
      await 状态.写入器.write(数据);
    });
    return 状态.写入链;
  };
  const 清空等待队列 = async () => {
    if (!状态.写入器) {
      return;
    }
    while (状态.等待队列.length && !状态.已关闭) {
      const 数据块 = 状态.等待队列.shift();
      await 状态.写入器.write(数据块);
    }
  };
  const 加密记录 = async (明文) => {
    if (!状态.服务端子密钥) {
      状态.服务端盐 = crypto.getRandomValues(new Uint8Array(盐长度));
      状态.服务端子密钥 = await 派生子密钥(主密钥, 状态.服务端盐);
      状态.服务端随机数 = new Uint8Array(随机数长度);
    }
    const 长度字节 = new Uint8Array(2);
    长度字节[0] = (明文.length >> 8) & 0xff;
    长度字节[1] = 明文.length & 0xff;
    const 长度密文 = await 加密(状态.服务端子密钥, 状态.服务端随机数, 长度字节);
    增加随机数(状态.服务端随机数);
    const 数据密文 = await 加密(状态.服务端子密钥, 状态.服务端随机数, 明文);
    增加随机数(状态.服务端随机数);
    const 记录 = new Uint8Array(长度密文.length + 数据密文.length);
    记录.set(长度密文);
    记录.set(数据密文, 长度密文.length);
    return 记录;
  };
  const 加密并发送 = async (明文) => {
    const 记录 = await 加密记录(明文);
    if (!状态.已发送服务端盐) {
      状态.已发送服务端盐 = true;
      const 完整 = new Uint8Array(盐长度 + 记录.length);
      完整.set(状态.服务端盐);
      完整.set(记录, 盐长度);
      服务端.send(完整);
    } else {
      服务端.send(记录);
    }
  };
  const 启动读取 = async (套接字, 读取器, 直连) => {
    let 已收到数据 = false;
    try {
      while (!状态.已关闭) {
        const 结果 = await 读取器.read();
        if (结果.done) {
          if (直连 && !已收到数据 && !状态.已关闭) {
            return false;
          }
          return true;
        }
        if (结果.value && 结果.value.byteLength) {
          已收到数据 = true;
          await 加密并发送(结果.value);
        }
      }
      return true;
    } finally {
      try {
        读取器.releaseLock();
      } catch {}
      if (状态.读取器 === 读取器) {
        状态.读取器 = null;
      }
    }
  };
  const 连接转发 = async (目标) => {
    let 直连套接字 = null;
    try {
      try {
        直连套接字 = await 创建套接字(目标.主机, 目标.端口);
        if (状态.已关闭) {
          await 关闭套接字(直连套接字);
          return;
        }
        状态.套接字 = 直连套接字;
        状态.写入器 = 直连套接字.writable.getWriter();
        await 清空等待队列();
        const 直连读取器 = 直连套接字.readable.getReader();
        状态.读取器 = 直连读取器;
        const 直连完成 = await 启动读取(直连套接字, 直连读取器, true);
        if (直连完成) {
          return;
        }
      } catch {}
      if (状态.已关闭) {
        return;
      }
      try {
        状态.读取器?.cancel();
      } catch {}
      try {
        状态.读取器?.releaseLock();
      } catch {}
      try {
        状态.写入器?.releaseLock();
      } catch {}
      状态.读取器 = null;
      状态.写入器 = null;
      await 关闭套接字(状态.套接字);
      状态.套接字 = null;
      const 代理套接字 = await 创建套接字(代理.hostname, 代理.port);
      if (状态.已关闭) {
        await 关闭套接字(代理套接字);
        return;
      }
      状态.套接字 = 代理套接字;
      状态.写入器 = 代理套接字.writable.getWriter();
      await 清空等待队列();
      const 代理读取器 = 代理套接字.readable.getReader();
      状态.读取器 = 代理读取器;
      await 启动读取(代理套接字, 代理读取器, false);
    } finally {
      try {
        状态.读取器?.cancel();
      } catch {}
      try {
        状态.读取器?.releaseLock();
      } catch {}
      try {
        状态.写入器?.releaseLock();
      } catch {}
      await 关闭套接字(状态.套接字);
      状态.读取器 = null;
      状态.写入器 = null;
      状态.套接字 = null;
    }
  };
  const 处理接收数据 = async () => {
    while (!状态.已关闭) {
      if (!状态.已读客户端盐) {
        if (状态.接收缓冲.length < 盐长度) {
          return;
        }
        const 盐 = 状态.接收缓冲.subarray(0, 盐长度);
        消费缓冲(盐长度);
        状态.客户端子密钥 = await 派生子密钥(主密钥, 盐);
        状态.客户端随机数 = new Uint8Array(随机数长度);
        状态.已读客户端盐 = true;
      }
      if (状态.接收缓冲.length < 2 + 标签长度) {
        return;
      }
      const 长度密文 = 状态.接收缓冲.subarray(0, 2 + 标签长度);
      let 长度明文;
      try {
        长度明文 = await 解密(状态.客户端子密钥, 状态.客户端随机数, 长度密文);
      } catch {
        await 全部关闭();
        return;
      }
      增加随机数(状态.客户端随机数);
      const 载荷长度 = (长度明文[0] << 8) | 长度明文[1];
      if (载荷长度 > 0x3fff) {
        await 全部关闭();
        return;
      }
      const 需要长度 = 2 + 标签长度 + 载荷长度 + 标签长度;
      if (状态.接收缓冲.length < 需要长度) {
        return;
      }
      消费缓冲(2 + 标签长度);
      const 数据密文 = 状态.接收缓冲.subarray(0, 载荷长度 + 标签长度);
      消费缓冲(载荷长度 + 标签长度);
      let 数据明文;
      try {
        数据明文 = await 解密(状态.客户端子密钥, 状态.客户端随机数, 数据密文);
      } catch {
        await 全部关闭();
        return;
      }
      增加随机数(状态.客户端随机数);
      if (!状态.已初始化) {
        const 目标 = 解析影梭头(数据明文);
        状态.已初始化 = true;
        const 初始载荷 = 目标.载荷;
        if (初始载荷 && 初始载荷.byteLength) {
          状态.等待队列.push(new Uint8Array(初始载荷));
        }
        if (!状态.正在连接) {
          状态.正在连接 = true;
          连接转发(目标).catch(() => {
            全部关闭();
          });
        }
      } else {
        await 写入上游(数据明文);
      }
    }
  };
  服务端.addEventListener("message", async (事件) => {
    if (状态.已关闭) {
      return;
    }
    try {
      const 数据 = await 获取网套数据(事件.data);
      if (!数据 || !数据.byteLength) {
        return;
      }
      合并缓冲(数据);
      await 处理接收数据();
    } catch {
      await 全部关闭();
    }
  });
  服务端.addEventListener("close", () => {
    全部关闭();
  });
  服务端.addEventListener("error", () => {
    全部关闭();
  });
  return new Response(null, { status: 101, webSocket: 客户端 });
}
export default {
  async fetch(请求, env) {
    PASSWORD = env.pass || PASSWORD;
    PROXYIP = env.pyip || PROXYIP;
    const 网址对象 = new URL(请求.url);
    const 路径 = decodeURIComponent(网址对象.pathname);
    const 升级 = 请求.headers.get("Upgrade");
    const 是否网套 = 升级 && 升级.toLowerCase() === "websocket";
    if (是否网套 && (路径 === "/" || 路径.startsWith("/pyip="))) {
      return 处理网套请求(请求);
    }
    if (路径 === `/${PASSWORD}` || 路径 === `/${PASSWORD}/`) {
      return new Response("OK");
    }
    return fetch("https://www.cctv.com");
  }
};
