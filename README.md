Project Description: PIHASH Password Manager
PIHASH is a Java-based password manager application designed to securely store and manage user credentials for various websites.
It provides a graphical user interface (GUI) built with Swing, allowing users to sign up, log in, and manage their credentials in a personal vault. The application uses AES encryption to secure passwords,
storing them in encrypted form in user-specific vault files. Key features include:

User Authentication: Users can sign up with personal details and a master password, then log in to access their vault.
Password Management: Add, edit, delete, search, and generate strong passwords for different sites.
Encryption: Utilizes AES encryption to secure passwords, with the master password serving as the encryption key.
Vault Storage: Each user has a dedicated vault file (vaults/username.txt) to store encrypted credentials.
Import/Export: Supports exporting and importing vault files for backup or transfer.
Password Generation: Generates secure, random 16-character passwords with a mix of letters, numbers, and special characters.
User-Friendly Interface: Features a dark-themed GUI with background images for login, signup, and vault screens.
