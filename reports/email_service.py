import smtplib
from email.message import EmailMessage
import os

def send_report_email(smtp_server, smtp_port, sender, recipients, subject, html_content, attachment_path, attachment_name):
    """Envia o e-mail com o corpo HTML renderizado e o arquivo anexado."""
    if not recipients:
        print("[AVISO] E-mail habilitado, mas nenhum destinatário configurado.")
        return False

    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = ", ".join(recipients)
    
    # Define o corpo principal como HTML
    msg.set_content("Este é um relatório HTML. Por favor, utilize um cliente de e-mail compatível.")
    msg.add_alternative(html_content, subtype='html')

    # Anexa o arquivo consolidado original
    if attachment_path and os.path.exists(attachment_path):
        with open(attachment_path, 'rb') as f:
            file_data = f.read()
        msg.add_attachment(file_data, maintype='text', subtype='html', filename=attachment_name)
    else:
        print("[AVISO] Arquivo de anexo não encontrado. E-mail será enviado sem anexo.")

    try:
        # Envio sem autenticação na porta configurada (default: 25)
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.ehlo()
            # Tenta usar TLS apenas se o servidor suportar ativamente, caso contrário prossegue normalmente
            if server.has_extn('STARTTLS'):
                try:
                    server.starttls()
                    server.ehlo()
                except Exception as e:
                    print(f"[AVISO] Servidor anunciou STARTTLS mas houve falha na negociação, prosseguindo sem TLS: {e}")
            
            server.send_message(msg)
            
        print(f"[OK] E-mail enviado com sucesso para: {', '.join(recipients)}")
        return True
    except Exception as e:
        print(f"[ERRO] Falha de conexão/envio SMTP ao enviar e-mail: {e}")
        return False