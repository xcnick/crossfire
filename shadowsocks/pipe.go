package shadowsocks

import (
	"net"
	"time"
)

func SetReadTimeout(c net.Conn) {
	if readTimeout != 0 {
		c.SetReadDeadline(time.Now().Add(readTimeout))
	}
}

func PipeThenClose(src, dst net.Conn, addTraffic func(int)) {
	defer dst.Close()
	// 获取一个用于读数据的buffer
	buf := leakyBuf.Get()
	// 方法执行完毕后，归还该读取buffer
	defer leakyBuf.Put(buf)
	for {
		SetReadTimeout(src)
		n, err := src.Read(buf)
		if addTraffic != nil {
			addTraffic(n)
		}
		if n > 0 {
			if _, err := dst.Write(buf[0:n]); err != nil {
				Debug.Println("write:", err)
				break
			}
		}
		if err != nil {
			break
		}
	}
	return
}
