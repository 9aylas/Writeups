# Autoexp writeup

首先，膜冠城大佬。

然后，晨升恐惧症又发作了，膜。

这个题目我发现了两处漏洞，应该还有没发现的一个，求指导。

## 1. 堆溢出

漏洞位于0x040173A的comment修改中，此处如果长度输入-1将会有无限的堆操作能力，任意的堆覆盖。

![alt](https://raw.githubusercontent.com/unamer/Writeups/master/ichunqiu-Final/1.jpg)

这导致可以直接覆写下一个fun结构的头部指针，我通过覆盖函数结构头部的paramlist指针链表来得到任意地址写，当然首先需要布置好链表的结构。

在0x00401D4F的editend函数中，允许对全局变量buf进行任意修改，我就利用这个固定的地址写入paramlist指针，指向atoi之前的8个字节。

![alt](https://raw.githubusercontent.com/unamer/Writeups/master/ichunqiu-Final/2.jpg)

完整的exp见[autoexp.py](autoexp.py)

## 2.UAF

漏洞还是在于comment，但是这次是comment之后如果删除这个这个fun结构再次创建一个fun的话，comment指针实际上free掉了并没有置零。造成一个uaf。

利用首先控制第一次comment的大小为22（malloc大小24），然后在创建新的fun的时候，datalist指针和comment指针将会指向同一块内存，通过修改comment导致任意地址读取和写入，和上一个相同的方法拿到shell

完整exp见[autoexp2.py](autoexp2.py)

## 3.空指针崩溃

这个漏洞不知道怎么利用，只能造成DOS的效果。漏洞位于函数0x401518。

![alt](https://raw.githubusercontent.com/unamer/Writeups/master/ichunqiu-Final/3.jpg)

如果输入错误这个地方会崩溃，但不知如何利用。

## 4.File object覆盖

这个漏洞同不知道如何利用，漏洞位于0x00401D48那个memcpy中，关键在于sprintf的返回值不是那个参数2可以限制的，最大可用返回值是0x492

然后这会覆盖后面的stdout指针，导致崩溃。

![alt](https://raw.githubusercontent.com/unamer/Writeups/master/ichunqiu-Final/2.jpg)

但是后面覆盖的内容不知道如何控制，栈内容不可控导致无法利用。如果有大神能利用求告知。



