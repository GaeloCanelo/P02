use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Message {
    /// Cliente se conecta con un nombre de usuario y su llave pública
    Register {
        username: String,
        public_key_pem: String,
    },
    /// Servidor informa a todos de la lista actual de clientes conectados
    ClientList(Vec<(String, String)>), // username, public_key_pem
    /// Un cliente envía a otro el archivo
    SendFile {
        from: String,
        to: String,
        /// La llave AES generada aleatoriamente, cifrada con la llave RSA pública del receptor
        encrypted_aes_key: Vec<u8>,
        /// El contenido de p.txt, cifrado con la llave AES (usando AES ECB simple)
        encrypted_file_data: Vec<u8>,
    },
    /// Servidor devuelve un error simple
    Error(String),
}
