# rdp_mitm detect：

检测RDP中间人。

首先探测目标RDP服务端RTT和TLS实现特征，基于随机森林分类器判断RDP服务端是不是MITM。

```shell
//需要在linux下运行
sudo apt-get install python3-venv

cd rdpmitm_prober

python3 -m venv rdp-venv

source rdp-venv/bin/activate

pip install -r requirements.txt

sudo rdp-venv/bin/python3 rdpmitm_prober.py rdp_ip
//rdp_ip为待测rdp服务端ip
```

data文件夹中为分类器训练代码和数据。
