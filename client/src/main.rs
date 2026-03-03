use eframe::egui;
use shared::protocol::Message;
use shared::rsa_utils::{generate_rsa_keys, pub_key_to_pem};
use rsa::{RsaPrivateKey, RsaPublicKey};
use bytes::Bytes;
use std::sync::{Arc, Mutex};
use tokio::net::TcpStream;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use futures::sink::SinkExt;
use futures::stream::StreamExt;
use tokio::sync::mpsc;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> eframe::Result<()> {
    // Inicializar GUI
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([500.0, 400.0]),
        ..Default::default()
    };
    eframe::run_native(
        "P02 - Cifrado Híbrido",
        options,
        Box::new(|_cc| Ok(Box::new(ClientApp::new()))),
    )
}

struct AppState {
    username: String,
    connected: bool,
    users: std::collections::HashMap<String, String>,
    selected_user: String,
    file_path: Option<PathBuf>,
    status_msg: String,
    
    // Crypto
    priv_key: RsaPrivateKey,
    pub_key_pem: String,
}

struct ClientApp {
    state: Arc<Mutex<AppState>>,
    tx_to_server: Option<mpsc::Sender<Message>>,
}

impl Default for ClientApp {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientApp {
    fn new() -> Self {
        let (priv_key, pub_key) = generate_rsa_keys();
        let pub_key_pem = pub_key_to_pem(&pub_key);

        let state = Arc::new(Mutex::new(AppState {
            username: String::new(),
            connected: false,
            users: std::collections::HashMap::new(),
            selected_user: String::new(),
            file_path: None,
            status_msg: "Desconectado".to_string(),
            priv_key,
            pub_key_pem,
        }));

        Self {
            state,
            tx_to_server: None,
        }
    }

    fn connect(&mut self, ctx: egui::Context) {
        let state_clone = self.state.clone();
        
        let (tx, mut rx) = mpsc::channel::<Message>(32);
        self.tx_to_server = Some(tx.clone());

        tokio::spawn(async move {
            let stream_result = TcpStream::connect("127.0.0.1:8080").await;
            
            if let Ok(stream) = stream_result {
                let mut framed = Framed::new(stream, LengthDelimitedCodec::new());
                
                // Enviar Register inicial
                let reg_msg = {
                    let guard = state_clone.lock().unwrap();
                    Message::Register {
                        username: guard.username.clone(),
                        public_key_pem: guard.pub_key_pem.clone(),
                    }
                };
                
                let _ = framed.send(Bytes::from(bincode::serialize(&reg_msg).unwrap())).await;
                
                {
                    let mut guard = state_clone.lock().unwrap();
                    guard.connected = true;
                    guard.status_msg = "Conectado al servidor Relay".to_string();
                }
                ctx.request_repaint();

                // Bucle de lectura
                loop {
                    tokio::select! {
                        result = framed.next() => {
                            match result {
                                Some(Ok(bytes)) => {
                                    if let Ok(msg) = bincode::deserialize::<Message>(&bytes) {
                                        handle_server_message(msg, state_clone.clone(), ctx.clone());
                                    }
                                }
                                _ => {
                                    let mut guard = state_clone.lock().unwrap();
                                    guard.connected = false;
                                    guard.status_msg = "Conexión perdida".to_string();
                                    ctx.request_repaint();
                                    break;
                                }
                            }
                        }
                        
                        Some(out_msg) = rx.recv() => {
                            let b = bincode::serialize(&out_msg).unwrap();
                            if framed.send(Bytes::from(b)).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            } else {
                let mut guard = state_clone.lock().unwrap();
                guard.status_msg = "Error al conectar con 127.0.0.1:8080".to_string();
                ctx.request_repaint();
            }
        });
    }

    fn send_file(&self, to_user: String) {
        let guard = self.state.lock().unwrap();
        if let Some(path) = &guard.file_path {
            if let Ok(content) = std::fs::read(path) {
                let tx = self.tx_to_server.clone().unwrap();
                let username = guard.username.clone();
                let dest_pub_key_pem = guard.users.get(&to_user).cloned();

                if let Some(pem) = dest_pub_key_pem {
                    tokio::spawn(async move {
                        // 1. Generar AES y cifrar archivo
                        let aes_key = shared::aes_utils::generate_aes_key();
                        let encrypted_file_data = shared::aes_utils::encrypt_aes(&aes_key, content);

                        // 2. Parsear llave pública del receptor y cifrar llave AES
                        let dest_pub_key = shared::rsa_utils::pem_to_pub_key(&pem);
                        let encrypted_aes_key = shared::rsa_utils::encrypt_rsa(&dest_pub_key, &aes_key);

                        // 3. Enviar mensaje
                        let msg = Message::SendFile {
                            from: username,
                            to: to_user,
                            encrypted_aes_key,
                            encrypted_file_data,
                        };
                        let _ = tx.send(msg).await;
                    });
                } else {
                    println!("No se encontró la llave pública del usuario {}", to_user);
                }
            }
        }
    }
}

fn handle_server_message(msg: Message, state: Arc<Mutex<AppState>>, ctx: egui::Context) {
    let mut guard = state.lock().unwrap();
    match msg {
        Message::ClientList(list) => {
            guard.users = list.into_iter().map(|(n, p)| (n, p)).collect();
            let my_username = guard.username.clone();
            guard.users.retain(|u, _| u != &my_username);
        }
        Message::SendFile { from, encrypted_aes_key, encrypted_file_data, .. } => {
            println!("Recibiendo archivo de {}...", from);
            // 1. Descifrar llave AES usando llave RSA PRIVADA local
            let aes_key_bytes = shared::rsa_utils::decrypt_rsa(&guard.priv_key, &encrypted_aes_key);
            
            if aes_key_bytes.len() == 32 {
                let mut aes_key = [0u8; 32];
                aes_key.copy_from_slice(&aes_key_bytes);
                
                // 2. Descifrar el archivo usando la llave AES
                let file_data = shared::aes_utils::decrypt_aes(&aes_key, encrypted_file_data);
                
                // Guardar como p_recibido.txt en el escritorio como comprobación
                if let Ok(desktop_path) = std::env::var("USERPROFILE") {
                    let mut path = PathBuf::from(desktop_path);
                    path.push("Desktop");
                    path.push(format!("p_recibido_de_{}.txt", from));
                    let _ = std::fs::write(&path, file_data);
                    guard.status_msg = format!("¡Archivo guardado en {:?}", path);
                }
            } else {
                guard.status_msg = "Error: La longitud de la llave AES descifrada no es 32 bytes".to_string();
            }
        }
        Message::Error(e) => {
            guard.status_msg = format!("Servidor: {}", e);
        }
        _ => {}
    }
    ctx.request_repaint();
}

impl eframe::App for ClientApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui: &mut egui::Ui| {
            ui.heading("Sistema Distribuido (RSA + AES)");
            ui.separator();

            let mut state = self.state.lock().unwrap();

            if !state.connected {
                ui.horizontal(|ui: &mut egui::Ui| {
                    ui.label("Usuario:");
                    ui.text_edit_singleline(&mut state.username);
                });
                
                if ui.button("Conectar").clicked() && !state.username.is_empty() {
                    drop(state); // Liberar lock antes de connect
                    self.connect(ctx.clone());
                    return;
                }
            } else {
                ui.horizontal(|ui: &mut egui::Ui| {
                    ui.label(format!("Conectado como: {}", state.username));
                });
                
                ui.separator();
                
                ui.horizontal(|ui: &mut egui::Ui| {
                    if ui.button("Seleccionar Archivo (p.txt)").clicked() {
                        if let Some(path) = rfd::FileDialog::new().pick_file() {
                            state.file_path = Some(path);
                        }
                    }
                    if let Some(path) = &state.file_path {
                        ui.label(format!("Seleccionado: {:?}", path.file_name().unwrap()));
                    }
                });

                ui.horizontal(|ui: &mut egui::Ui| {
                    ui.label("Enviar a:");
                    let users_clone = state.users.clone();
                    egui::ComboBox::from_id_source("users_combo")
                        .selected_text(&state.selected_user)
                        .show_ui(ui, |ui: &mut egui::Ui| {
                            for (user, _) in &users_clone {
                                ui.selectable_value(&mut state.selected_user, user.clone(), user);
                            }
                        });
                });

                if ui.button("ENVIAR").clicked() && state.file_path.is_some() && !state.selected_user.is_empty() {
                    let to_user = state.selected_user.clone();
                    drop(state); // Libera lock
                    self.send_file(to_user);
                    return;
                }
            }

            ui.separator();
            ui.label(&state.status_msg); // Actualizada en handle_server_message o connect
        });
    }
}
