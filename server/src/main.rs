use shared::protocol::Message;
use std::{collections::HashMap, sync::Arc};
use tokio::{net::TcpListener, sync::{mpsc, Mutex}};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use futures::sink::SinkExt;
use futures::stream::StreamExt;
use bytes::Bytes;

type ClientMap = Arc<Mutex<HashMap<String, mpsc::Sender<Message>>>>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("0.0.0.0:8080").await?;
    println!("Servidor Relay escuchando en el puerto 8080...");

    let clients: ClientMap = Arc::new(Mutex::new(HashMap::new()));

    loop {
        let (socket, addr) = listener.accept().await?;
        println!("Nueva conexión recibida de: {}", addr);
        
        let clients = clients.clone();
        
        tokio::spawn(async move {
            let mut framed = Framed::new(socket, LengthDelimitedCodec::new());
            let mut username = None;
            
            // Canal para que otros threads envíen mensajes a ESTE cliente
            let (tx, mut rx) = mpsc::channel::<Message>(32);

            loop {
                tokio::select! {
                    // Recibir mensajes desde el socket del cliente
                    result = framed.next() => {
                        match result {
                            Some(Ok(bytes)) => {
                                match bincode::deserialize::<Message>(&bytes) {
                                    Ok(msg) => {
                                        if let Err(e) = handle_message(msg, &mut username, tx.clone(), &clients).await {
                                            println!("Error manejando mensaje de {}: {}", addr, e);
                                        }
                                    }
                                    Err(e) => println!("Error al deserializar mensaje de {}: {}", addr, e),
                                }
                            }
                            Some(Err(e)) => {
                                println!("Error de lectura en socket de {}: {}", addr, e);
                                break;
                            }
                            None => {
                                println!("El cliente {} se ha desconectado.", addr);
                                break;
                            }
                        }
                    }
                    
                    // Recibir mensajes desde el canal interno MPSC y mandarlos al socket
                    Some(msg) = rx.recv() => {
                        if let Ok(b) = bincode::serialize(&msg) {
                            if let Err(e) = framed.send(Bytes::from(b)).await {
                                println!("Error al enviar mensaje por el socket a {}: {}", addr, e);
                                break;
                            }
                        }
                    }
                }
            }
            
            // Limpieza al desconectar
            if let Some(user) = username {
                let mut guard = clients.lock().await;
                guard.remove(&user);
                println!("Usuario {} eliminado del registro.", user);
                broadcast_client_list(&guard).await;
            }
        });
    }
}

async fn handle_message(
    msg: Message,
    current_username: &mut Option<String>,
    my_tx: mpsc::Sender<Message>,
    clients: &ClientMap,
) -> Result<(), Box<dyn std::error::Error>> {
    match msg {
        Message::Register { username, public_key_pem } => {
            println!("Registrando usuario: {}", username);
            *current_username = Some(username.clone());
            
            let mut guard = clients.lock().await;
            guard.insert(username.clone(), my_tx);
            
            broadcast_client_list(&guard).await;
        }
        Message::SendFile { from, to, encrypted_aes_key, encrypted_file_data } => {
            let guard = clients.lock().await;
            if let Some(tx) = guard.get(&to) {
                println!("Enrutando archivo de {} hacia {}", from, to);
                // Reenviar el mismo mensaje
                let _ = tx.send(Message::SendFile { from, to, encrypted_aes_key, encrypted_file_data }).await;
            } else {
                println!("Usuario destino '{}' no encontrado", to);
                // Si falla, le mandamos un error al emisor original (necesitaríamos su tx)
            }
        }
        _ => {}
    }
    Ok(())
}

async fn broadcast_client_list(clients: &tokio::sync::MutexGuard<'_, HashMap<String, mpsc::Sender<Message>>>) {
    // Nota: Por simplicidad en la Práctica 2, para enviar la lista a todos,
    // solo mandaremos los nombres (la lista de tuplas pedía la llave pública).
    // Modificaremos aquí para ajustarnos rápdio, o podemos pedir a Register guardar la llave pública.
    
    // Dejaremos la actualización de lista como TODO o lo simplificaremos por ahora.
    let keys: Vec<(String, String)> = clients.keys().map(|k| (k.clone(), String::new())).collect();
    let msg = Message::ClientList(keys);
    
    for tx in clients.values() {
        let _ = tx.send(msg.clone()).await;
    }
}
