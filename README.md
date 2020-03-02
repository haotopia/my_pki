# 基于国标（06年）的PKI公钥密码系统

国标：

​	对称加密：SMS4

​	签名：ECDSA

​	密钥协商：ECDH

​	杂凑：SHA-26

写在前面：本次实验原本想尝试做一套CPK的系统（如果感兴趣可以了解一下CPK，我国第一套自主研发 ，世界第一个自证性密码体制），但是时间太急了就没做完，杂凑和对称密钥可能没按国标，不过后面会修改分支的，为了能验收只能先做一套PKI系统了。本次系统以了bcpkix和bcprov两个包为基础进行开发，证书标准为X.509。数据库用的sqlite。

## 一、PKI简介

PKI (Pubic Key Infrastructure)是一个用公钥密码学技术来实施和提供安全服务的安全基础设施，它是创建、管理、存储、分布和作废证书的一系列软件、硬件、人员、策略和过程的集合。PKI基于数字证书基础之上，使用户在虚拟的网络环境下能够验证相互之间的身份，并提供敏感信息传输的机密性、完整性和不可否认性，为电子商务交易的安全提供了基本保障。

## 二、项目简介

本项目实现的PKI系统包含如下组件：

### 2.1项目组成

#### （1）证书认证机构 CA（Certificate Authority） 

- 发放证书，用数字签名绑定用户或系统的识别号和公钥。 
- 规定证书的有效期。 
- 通过发布证书废除列表（CRL）确保必要时可以废除证书。 

#### （2）注册机构 RA（Registration Authority） 

- 接收用户的证书申请，审核用户的身份
- 为用户向 CA 提出证书请求
- 将申请的证书发放给用户

#### （3）证书分发系统 CDS（Certificate Distribution System） 

​	证书通过证书分发系统对外公开发布，用户可在此获取其它用户的证书。证书的发布可以有多种途径，比如，用户可以自己发布，或是通过目录服务器向外发布。本系统模拟了该过程。

​	本次项目采用X.509 格式的数字证书。

### 2.2基本流程

#### （1）颁发证书

从使用者角度来看，证书可以分为系统证书和用户证书。

首先用户到 CA 的注册机构 RA 或业务受理点或通过 web 网站等提交证书申请。如果用户自己产生公私钥对，证书申请中包含了个人信息和公钥；如果由 CA 产生公私钥，则证书申请中只包含个人信息。 

接着 RA 等机构对用户的信息进行审核，审核用户的相关关键资料和证书请求中是否一致，更高级别的证书需要 CA进行进一步的审核。 

审核通过后，CA 为审核此用户签发证书，证书可以灌制到证书介质中，发放给用户；或者将证书发布到 LDAP 服务器上，由用户下载并安装证书。

#### （2）废除证书

用户到 CA 的业务受理点申请废除证书，CA 审核用户的身份后，将证书吊销，并将吊销的证书加入到证书黑名单 CRL（Certificate Revocation List）中，CRL 是由 CA 认证中心定期发布的具有一定格式的数据文件，它包含了所有未到期的已被废除的证书（由 CA 认证中心发布）信息。CA 会临时或者定期签发证书黑名单 CRL，并将更新的 CRL 通过 LDAP目录服务器在线发布，供用户查询和下载。

#### （3）证书的更新

当用户的私钥被泄漏或证书的有效期快到时，用户应该更新私钥。这时用户可以申请更新证书，以废除原来的证书，产生新的密钥对和新的证书。证书更新的操作步骤与申请颁发证书的类似。

#### （4）证书验证

证书验证的内容包括三部分： 

- 验证有效性，即证书是否在证书的有效使用期之内？证书有效性的验证是通过比较当前时间与证书截止时间来进行的。 
- 验证可用性，即证书是否已废除？证书可用性的验证是通过证书撤销机制来实现的。 
- 验证真实性，即证书是否为可信任的 CA 认证中心签发。

### 2.2完成PKI系统生成证书的签名及加密消息传输过程

（1）数字签名

（2）电子信封