# Effective Authentication Mechanism for Vehicular Fog Infrastructure
I.  Security requirements in Vehicular Fog Infrastructure
  1. Vehicular Fog Infrastructure -VFC
  2. oneM2M-based Vehicular Fog Computing platform - oneVFC
  3. Security requirements during resource sharing

II. Authenticated encyption techniques and system models
  1. Authenticated encyption technique
  2. system model

III. Security testing and assessment results
  1. Simulation model
  2. Performance Evaluation
  3. Security Evaluation

## Abstract
Recently, a tangible vehicular fog computing (VFC)
platform based on oneM2M, called oneVFC, has been proposed.
This platform enabled federated AI learning, but did not include
sufficient attention to security. Therefore, this paper proposes
an effective authentication and key agreement protocol based
on the Elliptic curve cryptography (ECC) to enhance privacy
preservation in an authenticated way in order to ensure safer AI
training. Experimental results show that the proposed authentication mechanisms make reliable transmissions in highly-mobile
vehicular networks possible, resulting in a desirable quality of
service (QoS). The performance and security strength of two
authenticated encryption modes of AES, GCM and CCM, are
also compared and evaluated.

## I.  Security requirements in Vehicular Fog Infrastructure
###  1. Vehicular Fog Infrastructure -VFC
+ Overcome bandwidth and latency limitations.
+ Store, manage, and process data at the network edge close to user applications.
+ Respond to user applications in real time.

![image](https://github.com/user-attachments/assets/fe465a93-f3b1-43c5-ba61-8d4cfb76386f)

###  2. oneM2M-based Vehicular Fog Computing platform - oneVFC
+ OneVFC is a oneM2M based platform for managing computing and communication resources in vehicles (called Fog Worker nodes)
+ OneVFC can be used to train AI models using federated learning.
  
![image](https://github.com/user-attachments/assets/88d90b36-55b7-485b-a503-ced7548156ce)

### 3. Security requirements during resource sharing
Security requirements in training AI models using federated learning approach:
+ Fog worker nodes must be authenticated before performing computational services.
+ Data/model exchange must ensure security features including confidentiality, integrity, authenticity and non-repudiation.

![image](https://github.com/user-attachments/assets/485d22b1-d5fc-4414-b6d0-a5fa0de23f05)


## II. Authenticated encyption techniques and system models
###  1. Authenticated encyption technique
+ Identity and access management (IAM) systems are used to authenticate and authorize clients.
+ The authenticated encryption algorithm uses AES with Galois counter mode (GCM) and cipher-message block chaining counter mode (CCM) to ensure security features.

![image](https://github.com/user-attachments/assets/2a5b5ffd-821a-4acf-8c3b-4602f6ea7b00)

### 2. system model
The system model consists of 4 components:
+ IN-CSE server: authorizes Fog workers.
+ DAS Server: Issues tickets to Fog workers.
+ Fog Manager processes user service requests, authenticates them, and assigns tasks to Fog workers.
+ Fog Workers perform computational tasks.

![image](https://github.com/user-attachments/assets/9e46229d-53bd-403c-ab1a-0c96b6aad9e4)

The system implementation process includes 3 stages:
+ System initialization phase: DAS server, IN-CSE, and Fog worker generate private and public key pairs for themselves.

![image](https://github.com/user-attachments/assets/928a5ba8-4e80-4483-b152-1f9aafd19ca9)

![image](https://github.com/user-attachments/assets/03854af7-5c4a-40f0-b7c2-104d8e887035)

+ Registration and card receiving phase: Fog worker registers card and receives card from DAS.

![image](https://github.com/user-attachments/assets/6d16f1e1-58b5-4a1c-a9cf-fe1391e92eff)

![image](https://github.com/user-attachments/assets/73adb630-9bca-409d-835b-71363aadda80)

+ Key negotiation and training model sharing phase: Fog manager authenticates Fog worker's tag, if tag is authenticated successfully and Fog worker is authorized, Fog manager and Fog worker start session key negotiation and data sharing.

![image](https://github.com/user-attachments/assets/832f1f6c-90c3-4e96-a710-96c72ec4a9e4)

## III. Security testing and assessment results
### 1. Simulation model
![image](https://github.com/user-attachments/assets/c6e4bd48-26aa-4fd7-a7cf-165aec4fb62c)

### 2. Performane Evaluation
The system processing time when applying GCM mode has lower latency than CCM mode in both measurement models.
![image](https://github.com/user-attachments/assets/59e15b4a-6b86-4a82-9609-32a7813042a9)

### 3. Security Evaluation
+ The average CDR results of the two mechanisms GCM(≈ 95.06%) and CCM(≈ 93.25%) are both greater than 93%.
+ This result shows that the system can resist hackers from decoding the ciphertext.

![image](https://github.com/user-attachments/assets/6997fc78-9904-45da-8500-21c5eafd405a)

+ The average MDR results of GCM (≈93.84) and CCM (≈93.75) are both greater than 90%.
+ The MDR value shows how well the system can prevent hackers from discovering the cryptographic key.

![image](https://github.com/user-attachments/assets/d1c589e3-5ac3-45fd-bbff-7a34f4933909)

![image](https://github.com/user-attachments/assets/d33c6608-65df-4193-8e5e-ed152287ff2e)

More information at this papper: https://ieeexplore.ieee.org/document/9852081
