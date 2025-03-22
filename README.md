# Recoverbull: an encrypted Bitcoin wallet backup protocol

By Francis Pouliot and Jules Azad Emery

Version 1.0.0 - last updated on March 22 2025
  
## Abstract


*Bitcoin grants its users property rights over their money which can be asserted and enforced without relying on a trusted third party, as well as the ability to make peer-to-peer censorship-resistant payments with a high degree of anonymity. These properties emerge as a consequence of the user’s ability to generate and store the cryptographic keys required to create valid Bitcoin transactions, a process known as “self-custody”. In this paper, we highlight the many risks associated with self-custody of Bitcoin, particularly the loss or theft of Bitcoin private keys. We propose that the severity of these risks is a leading factor in a large and growing number of users choosing to interface with Bitcoin via third-party intermediaries that hold Bitcoin and make Bitcoin transactions on their behalf, commonly called “custodial wallets”. By using these intermediaries, users delegate the responsibility of securing access to their private keys to professional service providers, but they no longer benefit from Bitcoin’s core value proposition of self-sovereignty, censorship-resistance and privacy, in addition to exposing themselves to additional custody risks. In this paper, we develop a threat model that systematically reviews the risks associated specifically with creating backup copies of Bitcoin private keys. We propose a protocol for encrypting Bitcoin private key backups as well as software architecture specifications for its implementation. This software architecture for the reference implementation leverages cryptography techniques for encrypting private key backups, the use of commercial cloud storage providers for storing these backups, and a specialized service to host copies of encryption keys required to decrypt these backups. The protocol is designed to minimize single points of failure, preserve user anonymity and protect users against sophisticated attackers with state-level resources, for which a threat model is proposed. The protocol and reference implementation software are open-sourced under the permissive MIT license.*

- Server reference implementation: https://github.com/SatoshiPortal/recoverbull-server
- Client reference implementation: https://github.com/SatoshiPortal/recoverbull-client-dart
 
## Introduction to Bitcoin wallet backups

Self-custodial Bitcoin wallet applications generate private keys on the user’s device. These keys are never shared to a third party. This allows Bitcoin users to retain full sovereignty over their wealth. This comes with a crucially important responsibility: users must create and store a backup copy of their wallet’s private keys, otherwise they will lose access to their funds forever in the event that they lose access to the wallet application or device where their keys are stored.

In practice, this happens frequently. On a long enough timeline, it is guaranteed that a user will one day lose access to the wallet application or device which stores the private keys which allow him to sign valid Bitcoin transactions and consequently the ability to transfer or spend his Bitcoin. The user will have to perform a Bitcoin wallet recovery using a backup, for example as a result of one of these events:

-   The user’s phone or laptop is lost
    
-   The user’s phone or laptop is damaged
    
-   The user accidentally deletes the wallet application and/or its data
    
-   Application data is corrupted
    
-   The user loses access credentials to the application (e.g. his PIN, password)
    
-   A software or device bug prevents the user from using his wallet application
   
In 2013, a solution was proposed to facilitate the creation and storage of Bitcoin private key backups: mnemonic codes. Designed by Marek Palatinus (Slush), Pavol Rusnak (Stick), Aaron Voisine and Sean Bowe, this concept has become an almost universally accepted Bitcoin wallet standard via Bitcoin Improvement Proposal 39 (BIP39).

The concept is simple and brilliant: the entropy used to deterministically derive the wallet’s private keys is visually represented as a list of 12 or 24 words selected from a list of 2048 words (referred to as the BIP39 word list).

 This list of words is known colloquially under many names such as “seed”, “seed phrase”, “backup phrase”, “mnemonic”, “backup words”, “recovery phrase”, etc.

To recover access to his Bitcoin, the user enters the mnemonic into a BIP39-compatible Bitcoin wallet application which will use it to derive the private keys of the wallet, thereby recovering access to the Bitcoin. This method is easy to use, standardized and beginner-friendly. The major advantage of this method is that it facilitates the creation of offline backups which, typically, means writing down the mnemonic on a physical medium such as paper or metal.

To mitigate the risks of a stolen backup, users are often encouraged to add a BIP39 passphrase to their Bitcoin wallet, which will be generated using a 12 or 24 word mnemonic, but with the addition of a final word chosen by the user. This word can be a series of words, characters and numbers. It is colloquially referred to as a “passphrase” and effectively acts as the 13th or 25th word of the mnemonic.

In practice, however, this method poses significant security risks for end-users. The risks associated with creating and securing Bitcoin wallet mnemonic backups are so severe that it has become commonplace to discourage Bitcoin users from using self-custodial wallets altogether, and instead use custodial wallets that can be accessed and recovered using traditional authentication methods such as email-based accounts or phone numbers.

Note here that other backup formats exist, such as Bitcoin core's .dat file or Wasabi Wallet's wallet file. We assume however that the vast majority of users are using the BIP39 method, or non-standard variants such as Electrum Wallet's “Seed Version System” or Muun wallet's “Emergency Kit and Recovery Codes”.

### Backup risks and issues

In this review we focus exclusively on two self-custodial wallet arrangements: simple single-signature wallets and passphrase-protected single-signature wallets, which are the two most commonly used arrangements.

  We exclude from this review arrangements that Bitcoin users may employ such as collaborative custody (multisignature wallets) and timelocks. These techniques also require users to create Bitcoin wallet backups, but have different threat models and mitigations against backup risks.

  There are generally four major risks associated with mnemonic backups:

1.  Not doing the backup
    
2.  Accidental loss or destruction of the backup medium
    
3.  Compromised access to the backup medium (theft)
    
4.  Accidental loss of the BIP39 passphrase
    
#### Not doing the backup

The user may not be aware that a wallet backup is required, because he is not instructed or reminded to do so by the Bitcoin wallet application he is using. He may be aware, but not take the responsibility seriously. He may choose to do the backup at a later time because, at the time of wallet creation, he doesn't have access to a physical medium, or he is installing a Bitcoin wallet at a time and place which is not conducive to creating a backup, and put off the task indefinitely, or forget it altogether.

#### Accidental loss or destruction of the backup medium

We assume that the default best-case behavior of a typical user will be to write down the mnemonic backup on a piece of paper and hide it somewhere on their property.

Because many wallet applications force the user to prove that they have written down a backup upon wallet creation, and because the time of wallet creation may not provide the optimal circumstances to write down a backup, the user may be careless in writing his backup on an insecure medium, and promptly lose the backup.

A typical example of this would be a user creating a wallet backup during a meeting with friends, writing down the backup on a napkin or piece of paper, crumbling it in his pocket, and forgetting about it.

In the worst cases, users will store the mnemonics digitally on a device, as a screenshot or in plain text. This behavior is encouraged by the fact that many wallet applications immediately require the user to prove that he has written down the backup at the moment of wallet creation. The user is “rushed” into making a backup at an inopportune time, while all he wants to do at this time is explore the functionalities and user experience of a new app he just downloaded.

Even in the best case scenario of the user correctly writing down his backup on a more durable paper medium at an opportune moment, the paper medium may be destroyed during a natural disaster (flood, fire). Some physical media like paper will simply degrade over time and become illegible. The physical medium may be lost (thrown away accidentally, forgotten or dropped during moving, kept in a wallet or handbag and lost, etc. The user may also simply forget where he has hidden the backup.

There exist multiple products on the market that allow users to “engrave” or otherwise “inscribe” their mnemonic backups on metal using DIY methods. This mitigates the problem of the backup medium being destroyed or degraded, but not being lost or stolen.

To be safe, it's standard practice to recommend users have a second copy of the backup medium in a geographically distinct location.

While there is no data available, we assume that only a small fraction of Bitcoin users will implement having geographically dispersed physical mnemonic backs on long-term resilient media.

#### The backup is stolen

A stolen backup is one of the most serious security risks associated with Bitcoin self-custody. Because of the relatively widespread adoption of cryptocurrency, many people have become aware that a list of random words found on a piece of paper or metal may contain bitcoins. Regardless of the cybersecurity procedures employed by the wallet application, or the sophistication of the hardware device used to generate the wallet and store the private keys, the security of the user's funds is only as good as the security of his backup. Whoever finds one of the backups can immediately recover the private keys and steal the bitcoins.

For digitally stored mnemonic devices, some examples of theft include:
-   The device had been compromised with malware or spyware at the moment of creating the backup (e.g. a clipboard hijacker or malicious keyboard application).  
-   There exist multiple malware specifically designed to search for strings on infected devices that resemble a mnemonic. 
-   The device can be stolen, and the encryption password bruteforced.
   
For physically stored backups, some examples of theft include:
-   Evil maid attack: someone snooping around the house.   
-   Targeted attack: a relative or friend with knowledge of the existence of a backup.
-   Opportunistic burglary: a thief finds a backup during a regular burglary, particularly if the backup is kept with other valuables such as a safe or jewelry box.
-   Raid or search: lawful or unlawful intrusion by authorities for a search related or unrelated to the Bitcoin, where the backup may be seized by authorities.

These risks are, at minimum, the same risks associated with safeguarding physical currency, precious metals or valuable art and jewelry.

The risks are exacerbated if the user keeps multiple copies of his backup in geographically diverse locations, as is good practice to prevent accidental loss or destruction of the backup, because it increases the surface and probability of an attack.

Some physical backup medium manufacturers have created products which help mitigate these risks. Some offer tamper-evident seals or locks, while others offer some level of obfuscation that make them look, to the untrained eye, as being ubiquitous objects that aren't obviously used for mnemonic backups.

#### Insecure BIP39 passphrase

If a malicious actor gains access to the mnemonic, they cannot access the funds without the passphrase. This effectively creates a 2-of-2 backup, where two parts of a secret need to be combined to recover the funds.

In practice, however, it is very hard for users to implement this strategy securely.

Users are notoriously bad at choosing strong passphrases. To make matters worse, most wallet software or hardware that require or allow the use of passphrases typically do not store the passphrase on the device. As a result, the user must enter his passphrase every time he wants to sign a Bitcoin transaction. This behavior incentivizes the user to use a memorable, and therefore low entropy, passphrase.

An attacker which has obtained a copy of a mnemonic backup can perform a bruteforce attack. This attack is not necessarily easy to perform. It requires the attacker being able to use software which will use as input the 12 or 24 words of the mnemonic, try to guess the passphrase, derive private keys from the mnemonic, and query the Bitcoin blockchain to determine if there are funds associated to these keys, all of this programmatically. To perform this attack successfully, an attacker would need technical skills and access to a powerful computer. The only "rate-limiting" factor is the time it takes for the attacker to scan the blockchain each time they perform a brute-force attempt. Even if the thief himself cannot perform this attack, it is not unlikely that he will be able to find a technically skilled collaborator that has the means.

In the best case, the user will have created a high entropy passphrase that is resistant to such bruteforce attacks. In a worse case, the user will have chosen a low entropy passphrase which will nonetheless reduce the attack surface and may have a false sense of security, which incentivizes him to be less careful when hiding his mnemonic backup. In the worst case, the user will keep a copy of his passphrase at the same location as his mnemonic backup, so that the attacker gets access to both simultaneously.

 
#### Lost BIP39 passphrase

If a BIP39 passphrase is bruteforce resistant, it's unlikely that the user will memorize it. Even a weak passphrase is hard to remember.

Forgetting or losing a BIP39 passphrase is one of the most common ways people lose access to their bitcoins. Consequently, the user is encouraged to create a physical or digital backup of their passphrase. This passphrase must be stored in a different location than their mnemonic backup, otherwise the passphrase defeats the purpose of acting as protection against evil maid attacks.

In addition, a second copy of the passphrase must be kept separately at another location, in case the first copy becomes inaccessible, damaged, lost or stolen.

If the user intends to make Bitcoin transactions on a regular basis, he needs to either memorize a bruteforce resistant passphrase (not an easy feat) or keep a copy of his passphrase in proximity of the device on which the Bitcoin wallet software is installed, while simultaneously making sure that an attacker that finds a copy of his mnemonic cannot easily find the copy of his passphrase. This can be achieved by storing the passphrase digitally, on a device, in the cloud or in a password manager.

  

## The Recoverbull Protocol

### Introduction

We propose the Recoverbull protocol which allows users to generate a secure encryption key, encrypt their mnemonic backups using this encryption key, save this encryption key with a 3rd party service (called the Key Server) and store their encrypted backup in a low-security location, such as a commercial cloud storage provider.

The fundamental premise and design goals of this protocol are as follows:

-   Bitcoins users can be uneducated, unwise, unmotivated, unskilled or incompetent. This should not preclude them from being able to backup their Bitcoin wallets securely.
    
-   Anonymity is inseparable from security. Any service or protocol that handles Bitcoin wallet backups should prioritize anonymity. Any information revealed by a Bitcoin user, including merely the fact that he owns Bitcoin, can be used against him by an attacker.
    
-   A backup process should be easy to complete in less than 5 minutes and maintain its security and anonymity regardless of the location or device of the end user.
    
-   Any service whose function is to facilitate Bitcoin wallet backups should avoid ever taking possession of user private keys, encrypted or otherwise, to avoid being classified as a money transmission service or virtual asset service provider.
    
-   An encrypted digital file is the safest way to protect a Bitcoin mnemonic from theft, if the encryption is strong enough to prevent brute-forcing and is performed in a device environment that is at least as secure as the one used for generating keys and signing transactions.
    
-   Humans are bad at generating strong passwords. Any encryption key should be randomly generated with sufficient entropy to prevent brute force attacks.
    
-   We cannot expect Bitcoin users to memorize randomly generated encryption keys with sufficient entropy.
    
-   Humans are bad at backing up their data, both sensitive and non-sensitive.
    
-   Password managers are, for most people, a convenient and secure way to backup their passwords. They are ubiquitous and part of people’s habits.
    
-   Cloud storage providers are, for most people, the best and easiest way to backup data to protect against accidental loss. They are ubiquitous and part of people’s habits.
    
-   Bitcoin users are more likely to be targeted by attackers trying to access their data than the average non-Bitcoin user.
    
We keep these principles in mind when designing our Bitcoin wallet backup protocol. We understand that there is a tradeoff between anonymity, security, convenience and reliability. We aim to provide a solution with tradeoffs that are acceptable for the majority of Bitcoin users. For users which have different tradeoff preferences which favor security and reliability over convenience, we offer alternative options within the same protocol.

 
### Key Server Backup protocol

-   We assume that the user is interacting with a Bitcoin wallet that has implemented the Recoverbull protocol. This wallet is henceforth referred to as the `Client`.
    
-   The `Client` generates a BIP39 mnemonic seed, henceforth referred to as `Mnemonic`.
    
-   The `Client` derives entropy from the mnemonic using BIP85. This entropy is referred to as the `Backup key`.
    
-   The `Client` encrypts the `Mnemonic` using the `Backup key` as the encryption key using AES. This creates the `Encrypted backup`.
    
-   The `Client` generates a random number hash called the `Identifier`
    
-   The `Client` generates a random `salt`
    
-   The `Client` generates a random nonce
    
-   The `Client` computes the mac
    
-   The `Client` concatenates nonce+`Encrypted backup`+mac to create the `Ciphertext`.
    
-   The `Client` generates the `Backup file` which contains the `Identifier` and `salt` and `Ciphertext`

> At this stage, the `client` has a local copy of the `Backup file`
> which contains the `Encrypted backup`. The `client` also has the
> `Backup key` which can decrypt the `Encrypted backup` to obtain the
> `Mnemonic`. 
> 
> The user can have the option to export the `Backup file` as well as
> the `Backup key` and store them independently in a custom location
> however he wishes. However, we assume that the user wants to continue
> with the Recoverbull Protocol.

 -   The `Client` requests that the user create a `Password`. The Recoverbull protocol is designed specifically for this Password to be memorable, therefore weak. The Bull Bitcoin Wallet implementation of the Recoverbull protocol requires a minimum 6 digit Password that is not found in a public list of the 1000 most common passwords.
    
 -   To strengthen the `Password`, we use the 16 bytes `Salt` stored in the Backup file, and combine it with the `Password` as input to the Argon2 key derivation function. Argon2 then derives a 64 bytes (512‑bit) key, split in two keys:
   
     - `Authentication Key` the first 32 bytes (256bits)  
     - `Encryption Key` the remaining 32 bytes 
    
 -   The `Client` encrypts the `Backup key` using `Encryption Key`.

> If only the Key Server database is compromised, the encryption
> effectively remains 128 bits strong due to the randomized salt.
> However, if an attacker also gains access to the Backup file
> containing that Salt, the overall security is reduced to the
> (potentially weak) Password itself, making brute-force attacks
> feasible. The Recoverbull protocol does not depend on this encryption
> as part of its core security model. However, if the user chooses a
> sufficiently strong Password, encrypting the Backup key not only
> avoids any negative tradeoff but also adds a layer of protection
> against the previously mentioned attacks.

 -   The `client` makes a store request to the `Key Server` with
     - `Identifier`
     - `Encrypted Backup Key`
     - `Authentication key`
   
-   The `Key Server` require the `Identifier` and `Authentication key` for two purposes:
     - Rate-limit brute-force attacks against a targeted `Identifier`
    - Compute the `Key ID` by hashing the `Identifier` and the `Authentication key.`

-   The `Key Server` creates a database entry with:
    -  `Key ID`
    -  `Time`
    - `Encrypted Backup Key`

-   The `Key Server` service should be rebooted daily to wipe Identifiers from the memory
    

> The whole point of the Recoverbull protocol is that the user can now
> store the Backup file in an otherwise insecure location such as a
> cloud storage provider. This part of the protocol can be implemented
> by the client in any way they choose. The following is an example from
> the Bull Bitcoin implementation.

-   The `Client` requests access to the user’s cloud storage account.
    
-   The `Client` creates an app folder.
    
-   The `Client` saves the `Backup file` in the app folder.
    
-   The backup protocol is complete.
    

### Key Server Recovery protocol

-   We assume that the `Client` has a copy of a `Backup file`. The user can have uploaded it manually or  fetched it from the user’s connected cloud storage account.
    
-   The `Client` needs the `Backup key` to decrypt the `Encrypted backup` contained in the `Backup file`. This can be provided by the user manually, but we assume that the user is using the `Key Server` to store his `Backup key`.
    
-   From the `Backup file` the `Client` obtains the `Identifier`, the `salt`, the MAC, the Nonce and the timestamp.
    
-   The `Client` requests user to provide his `Password`
    
-   The `Client` derives the `Authentication key` and `Encryption key` from the `Password` and the `salt`
    
-   The `Client` makes a fetch request to the `Key Server` with the `Identifier` and the `Authentication key.`
    
-   The `Key Server` hashes the `Identifier` with the `Authentication key` to determine the `Key ID`.

> The `Key Server` keeps the `Identifier` in memory to enforce rate
> limiting of fetch requests targeting the same Identifier. This way,
> someone that has obtained a copy of the `Backup file` cannot perform a
> brute-force attack to obtain the `Encrypted Backup Key`. Note here
> that while it would be better that the key server never receive any
> information that could link an `Encrypted Backup Key` to a specific
> `Backup file` it is necessary to prevent brute-forcing attacks, which
> is why the `Key ID` is computed using the `Identifier` and the
> `Authentication key` by  the `Key Server` instead of by the `Client`.

    
-   If a record exists for the computed `Key ID`, the `Key Server` is satisfied that whoever made the request must have been in possession of both the `Password` as well as the `Backup file` and therefore will release the `Encrypted Backup Key` to the `Client`.
    
-   The `Client` decrypts the `Encrypted Backup Key` using the `Encryption Key` to obtain the `Backup key`
    
-   The `Client` decrypts the `Encrypted backup` contained in the `Backup file` with the `Backup key` to obtain the `Mnemonic`
    
-   The `Client` restores the user's Bitcoin wallet using the `Mnemonic`
    
-   The recovery protocol is complete.
   
  

## Security model


The security model relies on four critical components:

-   Strong encryption
    
-   Segregated storage for a 2-of-2 backup
    
-   Rate-limit fetch requests to the Key Server
    
-   User anonymity

The security model of the Recoverbull protocol relies on securely encrypting a wallet backup data with a strong encryption key that cannot be bruteforced. This encrypted data can be stored in a reliable but relatively insecure location, such as a cloud storage provider. Because the entropy generated to create the encryption key to encrypt the mnemonic is derived from the mnemonic itself, the odds of an attacker bruteforcing the encrypted backup is roughly the same as the attacker guessing the mnemonic.

The main problem with strong encryption of a mnemonic is of course that the entropy of the encryption key is such that it cannot be remembered. The risk is that it will be lost, and that the backup cannot be decrypted. For this reason, we propose a free, anonymous and accountless narrow-purpose key management service, the Key Server.

  

Authentication with the Key Server is performed by the user with a password. Password bruteforcing is prevented by enforcing a strict limit at the Key Server level.

  

The user’s responsibility is to remember or store a password. The protocol is designed so that this password should be memorable and can be very weak. We expect that users are likely to choose the same 6 digit pin they use to unlock their mobile devices. This is fine, and is the whole point of the Recoverbull protocol. If users were able to generate and store bruteforce-resistant passwords by themselves, they could just use BIP39 passphrases.

  

An attacker that gets access to an encrypted backup cannot access the backup without the encryption key. An attacker that gets access to the encryption key cannot access the backup without the encrypted backup.

  

The Key Server correctly enforcing rate-limit of fetch requests is the most critical component of the Recoverbull protocol. A Recoverbull server could decide whatever rate-limiting parameters it wants. Our recommendation is a limit of 3 attempts per day per identifier. While other methods of rate-limiting may be useful (for example to prevent ddos attacks) they are not strictly required. The reason the rate-limit is so critical is that we expect the password chosen by the user to be very weak.

  

The most obvious attack vector for a secret storage in cloud storage is that a hacker will gain access to the cloud account and discover the encrypted backup. He will not be able to bruteforce it, but may attempt to retrieve the backup key from the Key Server. To do so, he would need to guess the password. A password even as weak as a 6-digit pin has 1,000,000 combinations, assuming that client-side validation prevents the user from choosing the most commonly used 6-digit pin patterns (for example, the top 50% chosen 6-digit pins). There is no way for the attacker to know whether the user has chosen a 6-digit pin, or any other type of password.

  

User anonymity is also a critical component of the security model. The key server should neither collect nor store any information that may be able to identify the user. In case the key server database is compromised, or in case the key server is malicious, any personal information could lead to targeted attacks against the user. Emails and phone numbers can be traced to the legal identity of an end-user, revealing that the end-user is a Bitcoin holder. In addition, emails and phone numbers can be used for phishing attacks, sim swap attacks or password reset attacks on a user’s cloud provider. For this reason, the Recoverbull protocol does not allow for password reset mechanisms, unlike the Photon protocol.

  

There is no reason for the Key Server to be able to communicate with users, except in the case of a security vulnerability that needs to be disclosed. This can be done anonymously, for example by clients using the nostr protocol to subscribe to events published by the key server. The data of the backup file gives no indication whether or not the user has stored a backup key on a key server, nor does it specify which key server has been used.

  

The key server does not have any method of identifying where the encrypted backup may be stored. This is why the protocol specifies that the key server should wipe the identifier from memory on a daily basis. The identifier is used to enforce rate-limiting, but since rate-limiting is enforced on a daily basis, the key server does not need to have the identifier for longer than 1 day. The identifier is the only link between an encrypted backup key and a backup file. Without the identifier, there is no way to know whether or not a specific backup key belongs to a specific backup file.

  

Even in the case of a legally binding request for information to obtain a backup key for a given backup file, the key server could not comply with that request, unless the user has performed a fetch request with the correct authentication key that same day.

  
  

  

## Implementation-level security features

### Rate limiting

The Key Server must enforce rate limiting of fetch requests. This is what allows the user to select a weak password. If rate limiting is not properly enforced, an attacker who stole a backup file, can obtain the backup key by guessing the password. Rate limiting is also why the Key Server keeps the identifier of a backup file in memory for a short period of time. If the rate limit period is 24h, the Key Server must keep the identifier in memory for 24h. Combined with the derivation of an authentication key, rate limiting based on the backup file identifier is what allows the user to authenticate himself anonymous without traditional account-based authentication. Users must trust the Key Server to correctly enforce rate limiting of fetch requests. To verify that the Key Server is properly enforcing rate limiting, user can attempt multiple fetch requests for a given backup file with incorrect passwords.

### Server health check

Every time the user opens the client and the client is connected to the internet, the client can check the info status of the Key Server and check if it is online. If the Key Server has not been online for some period of time determined by the client, the client can warn the user that the Key Server does not seem responsive and the user should stop relying on it for storing its backup key.

### Warrant canary

The Key Server can publish a warrant canary on its information endpoint. If the Key Server wants to communicate to the users that a law enforcement request has been served to the Key Server operator and the Key Server operator intends to comply or has already complied, the warrant canary is removed from the information endpoint. The client can warn the user to request Backup Key deletion, remove the Backup File from the cloud storage provider, or move funds to a new wallet entirely.

### Backup health check

The client should prompt the user to test the Recoverbull recovery flow at frequent intervals. This can allow the user to make sure that:

1.  The Backup File is accessible
    
2.  The Key Server is accessible
    
3.  The user remembers the password
    

### Key deletion

The Key Server should allow clients to request key deletion. This can be useful if a user suspects that the Backup File has been compromised.

### Key Rotation

Users can rotate their Backup Keys and Recovery Files at any time. This means in practice that they create a new Backup Key and a new Recovery File, and destroy their previous Recovery File. When doing so, if they have Social Recovery activated, the client must also send the new Backup Key to the Trusted Contact. The reason for key rotation is to protect the user in case the Key Server database is extracted and leaked. If such a leak happens, anyone with access to the Key Server database could attempt to gain access to the Secure Cloud Storage account of users in an attempt to find a Recovery File. Employees of the Secure Cloud Storage provider could also attempt this type of attack. By proposing Key Rotation on a frequent basis, the client can limit the user’s exposure to these types of attacks, especially when combined with Nostr alerts.

  
## Addendum: Social backup protocol

### Rationale

The social recovery protocol serves as an add-on to, or substitute for, the Key Server Backup Protocol. Its main function is to mitigate two risks associated with the Key Server Backup protocol:

1.  The Key Server is no longer reachable.
    
2.  The user forgets his Password
    
These two risks can be mitigated by the user creating a copy of his Backup Key himself and storing it on one of his devices.

However, we want to avoid the user saving his backup key on the device he uses for his Bitcoin wallet, which defeats the purpose if the device on which the wallet is installed is lost, or in the cloud alongside his Backup File.


The technique used by the Photon Protocol to mitigate the risk of the user forgetting his password is to allow the user to reset his PIN using a phone number or email address. This has numerous downsides and risks:

  
-   It puts the onus on the Key Server operator to verify the identity of the user via SMS or email, adding legal liability for the Key Server operator.
    
-   If the user's cloud account is hacked, there is a high chance that his email account is also hacked (and vice versa). Therefore, resetting a PIN by email opens up the attack surface considerably.
    
-   If a user's phone number is simswapped, there is a high likelihood that the attacker will also be able to gain access to the user's cloud account (via the cloud provider's account recovery process).
    
-   PIN resetting requires the Key Server Operator to store personal details of the user and associate them to his Key ID. In the event that the Key Server's database was hacked or leaked or accessed by any malicious actor, this information would enable an attacker to conduct targeted attacks against the users’ cloud accounts to obtain the Encrypted Backup File and decrypt the Backup Secret using the Backup Keys stored by the Key Server. If the Key Server holds no identifying information on the user whatsoever, this risk is dramatically reduced.
     

In addition, keeping personal information on users exposes the Key Server to law enforcement requests containing specific emails or phone numbers. For this reason, the Key Server should store no personal information whatsoever, including IP addresses.

  
### Social Recovery Protocol

The social recovery protocol is an alternative method for the user to store a backup key. Instead of or in addition to the key server, the user shares his backup with a trusted contact.

  
We must ensure that the Backup Key is encrypted with something stronger than just the password when the backup key is being shared, and that it is encrypted asymmetrically to the public key of the Trusted Contact. We must also ensure that the User is able to authenticate the Trusted Contact, and that the Trusted Contact is able to authenticate the user during a recovery.

We find that Nostr is an ideal solution to do so. Nostr identities can be used to authenticate the Trusted Contact and the User. The communications infrastructure exists separately from any single service provider (such as the Key Server) so it can continue to exist even if the Key Server operator goes offline.
 

We will demonstrate how to implement this protocol in practice:
 

1.  The Client will derives a Nostr private key from the user Mnemonic using BIP85
    
2.  The User will ask the Trusted Contact for his Nostr public key and import it into the Client.
    
3.  The Client will encrypt the Backup Key of the user to the Nostr public key of the Trusted Contact using NIP17.
    
4.  The User will encrypt his Backup Key using the Public Key of the Trusted Contact and send the Encrypted Backup key to the Trusted Contact as a Nostr direct message.
    
5.  If the User is unable to access the Key Server and needs to obtain a copy of his Backup Key, he can reach the Trusted Contact to recover his Backup Key
    
6.  The Trusted Contact should authenticate the user using the Nostr Public Key and asking personal questions to ensure the user is not impersonated.
    
7.  The Trusted Contacts send the Backup Key to the User.
    
  

## Threat model

#### Compromised Access to Recovery File  
  
Threat description

An attacker has gained access to the user’s Backup File, presumably by gaining access to his cloud storage account or hacking into a device where the Backup File was stored.

#### Mitigation measures

The attacker is unable to decrypt the encrypted backup of the user because it does not have the Backup Key. The attacker does not know which Key Server the user is using to store his backup key. Even if the attacker knows which Key Server the user is using (if any) the attacker cannot generate the authentication key to the Key Server without a password. In addition, the server enforces rate limiting on the identifier which is required for a key fetching request.

Likelihood: high

Severity: low

### Forgotten password

#### Threat description

The user forgets his password. He cannot fetch a backup key from the Key Server. The user can forget his password as long as he does not lose access to the Bitcoin wallet. If the user forgets the password and loses access to the Bitcoin wallet, the user will not be able to perform a recovery and his funds will be lost.

#### Mitigation measures

In order to mitigate this problem, the protocol is designed to allow for very weak passwords such as 6-digit PINs. It is the user's responsibility to remember or store this password. The user can download a copy of the Backup Key at any time and save it in a separate password manager or secure location. A client should implement frequent reminders for the user to test the backup by entering the password and doing a recovery. We recommend clients do this every 30 days. Another mitigation measure is the Nostr social recovery protocol, which would allow the user to share a copy of the backup key to a trusted contact. 

Likelihood: medium

Severity: medium

### Malicious Key Server (or hacked key Key Server) attempts to steal user backups

#### Threat description

A malicious Key Server has access to the user's Encrypted Backup Key, the user's Identifier, the user’s Authentication Key and the user's IP address. The attacker is the operator of the Key Server, running the service as a honey pot aiming to collect Backup Keys from its users, or an attacker which has taken control of the Key Server or has taken control of the Key Server’s domain and is running a Key Server under that domain.

#### Mitigation measures

The Key Server does not have access to the user’s Backup File and therefore cannot gain access to the user’s Bitcoin wallet. In order for an attack by a Malicious Key server to be successful, the Malicious Key Server operator needs to access the Backup file of the user. The Malicious Key Server also does not have access to the user’s email address or the user’s phone number, and does not know which cloud storage provider the user is using, nor does it know where the backup file could be. Consequently, it cannot perform a targeted attack on the user’s cloud storage provider. In addition, the backup key held by the Key Server is encrypted using the Encryption key derived from the user’s password and the 128 bits salt


Likelihood: low

Severity: medium

### Key server database is leaked to the public

#### Threat description

This scenario assumes that the key server database has fallen in the hands of an attacker, either the key server is malicious or the key server is hacked. The attacker decides to leak the key server database publicly. Malicious actors that had already gained unauthorized access to a backup file, or malicious gain access to backupfiles subsquently, can get access to the user's backup.
  
#### Mitigation measures

Backup keys held by the key server are encrypted. However, we assume that the encryption password is weak and that they will be bruteforced. One measure clients and users can employ is frequent key rotation. The main purpose of key rotation is to guard agains this threat specifically. When performing a key rotation, the user will effectively delete his existing backup file and create a new backup file with a new encryption key. We assume that the key server database leak is a one-off event and that the new encryption key will not be found in the publicly leaked database. The user is in danger in between the time the database is leaked and the time an attacker has gained access to his backup file. Key rotation will not help if the attacker already had access to the backup file prior to a key server database leak.

Likelihood: low

Severity: high

### Malicious cloud storage Provider and honest Key Server

#### Threat description

A malicious Cloud Storage Provider has the Backup File of the user, which contains the identifier, the salt and the Encrypted Backup. The attacker is either the management of the Cloud Storage Provider, or an employee with a high level of access.

The attacker is able to identify that some of its users are using the Recoverbull protocol by searching all files stored by the cloud provider and finding ones that fit the Recoverbull Backup file format.
  
#### Mitigation measures

The attacker does not know:
-   The backup key
-   Where the backup key is stored (locally or with a Key Server) and which Key Server is being used, if any.   
-   The user’s password  

The only useful piece of data that the cloud storage provider has is the identifier. In the case of an honest Key Server, the identifier is wiped from memory on a daily basis because it is only used for rate-limiting purposes.
 
Having the identifier in plaintext in the backup file is a deliberate decision. We cannot encrypt the Backup file with the user’s encryption key before upload to the cloud storage provider, because an attacker that gets access to the encrypted backup file could brute-force the encryption key offline without rate-limiting and guess the user’s password, which would allow the attacker to fetch the encrypted backup key from the key server. If we wanted to encrypt the backup file, we would need a second password from the user, which increases burdens on the end-user.
  
Likelihood: low

Severity: low

### Legal request at both Cloud Storage Provider and at the Key Server

#### Attack description

An entity with authoritative power, acting legitimately or illegitimately, acting in good faith or in bad faith, could make an access to information request to the Cloud Storage Provider for a specific User's cloud storage account. If the Cloud Storage Provider agrees to this request, the entity would likely find and gain access to the User's Backup File. By analyzing the format of the Backup File, the entity could identify that file as being compliant with the Recoverbull protocol, and attempt to seize the funds associated with the Mnemonic of the Encrypted Backup located in that file.


The entity cannot decrypt the file, because it does not have the Backup Key. The entity would then proceed with a legal request to Key Server to obtain the corresponding Backup Key.

#### Mitigation measures

Although the Key Server that hosts the backup key for that Backup File could be fully anonymous, unincorporated or incorporated in a jurisdiction which grants him legal protection to refuse the request, we assume that the Key Server may be obliged to respond to the request.

The Key Server only keeps the identifier of the backup file in memory for a short period of time.

The Key Server stores the Key ID and the Encrypted Backup Key. Without the Password or the Authentication key, the Key Server cannot comply with a request to provide a specific encrypted backup key. Unless a request is made to monitor any fetch request for the given identifier to share the corresponding Encrypted Backup Key. Without the authentication key, outside of the rate-limiting period, there is no other way for the Key Server to identify a specific backup file. The authentication key is never stored anywhere, and should not be made accessible to the user by a client for storage. It is generated on-the-fly by the user from the password every time the user makes a store or fetch request to the Key Server.

Even if the Key Server did comply with such a request, in the event that the request is made during the rate-limiting period following a store or fetch request by the user, the backup key is encrypted with the user’s password. We assume this will offer little protection because the password is likely to be weak and therefore can be bruteforced.
  
As a result, it is very unlikely that the Key Server will be able to comply with a request to provide an encrypted backup for a specific backup file. The request would need to be made for every single backup key hosted by the Key Server, which is a request that the Key Server could more easily refuse. In addition, backup keys are encrypted with the user’s password strengthened by the 128 bits salt. This is likely not going to be effective for most users who’s backup file and salt would have been compromised but the encryption will still remain as strong as the password.

In the event that the Key Server does decide to comply with a legal request to provide all the encrypted backup keys, a warrant canary can be used. When the warrant canary is removed, the client will detect it automatically once the user connects to the Key Server and can prompt the user to perform a key rotation.


Likelihood: low

Severity: high
  

### Malicious Key Server colludes with Malicious Cloud Storage Provider

#### Attack description

This attack involves a Malicious Cloud Storage Provider explicitly colluding with a Malicious Key Server for the purpose of acting as honey pots for Backup Files and Backup Keys. In practice, this means that high-ranking employees of Apple or Google are deliberately engaging in a criminal conspiracy, and are either in collusion with upper management at Apple or Google or able to bypass Apple and Google’s internal security procedures.

#### Mitigation measures

The only way to mitigate this type of attack is to trust the right Key Server and trust the right Cloud Storage Provider. Alternatively, users can choose to store the Backup Key or the Backup File in a more secure location.


Likelihood: extremely low

Severity: extremely high
 

### Key Server is no longer in service, or loses the Backup Keys

#### Problem description

The Key Server is no longer in service, or the Key Server has lost the backup keys. Users that have not created a physical backup of their mnemonics can no longer rely on the Key Server to fetch their Backup Key to perform a wallet recovery using the Recovery File.

#### Mitigation measures

Clients should check the Key Server’s status every time they are in use. Clients should notify the user if the Key Server has been inactive for a period of time. For example, if the Key Server has not made a status update post in 7 days, there is likely something wrong with the Key Server.
  
In this case, the client should notify the user that he should perform an alternative backup. The user can at any time download a copy of his Backup Key. He can later import the Backup Key into the client, and perform a recovery with the Backup File without ever needing to access the Key Server.  
  
We assume however that the user may have lost the device on which his Backup Key was stored. In this case, the user can use the Social Recovery feature.

Likelihood: medium

Severity: nedium

### User loses access to the Backup File

#### Problem description

The user may lose access to the Backup File for multiple reasons, such as losing access to the Cloud Storage account in which the Recovery File is stored. In addition, the user may have declined to store the Backup File with a Cloud Storage Provider and may have downloaded a copy which he kept on one of his own devices, and he has lost access to that device.

#### Mitigation measures

If the user still has access to his wallet, he should re-generate a new backup. If he can’t, there is little that the client, or the protocol in general, can do to mitigate this scenario. It is the user’s responsibility to keep store the Backup File, which is why the protocol suggests a user experience where the Backup File is stored on a Cloud Storage account. The user can download a copy of the Backup File and keep it offline, or store it in a password manager.


Likelihood: medium

Severity: nedium

## Catastrophic scenarios

  
List of catastrophic scenarios which can lead the user to lose his wallet:


-   Loss: user loses access to his device and to his Backup File
    
-   Loss: user loses access to his device and to the Key Server
    
-   Loss: user loses access to his device and to his password
    
-   Theft: user’s backup file is accessed by a malicious attacker and also knows the password.
    
-   Theft: the Key Server database is leaked publicly and a malicious attacker gains access to a backup file
    
-   Theft: the Key Server colludes with the cloud storage provider
    
-   Theft: the Key Server and the Cloud Storage Providers are both compelled by the same legal authority to give up their entire databases.

