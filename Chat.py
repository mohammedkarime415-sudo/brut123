import streamlit as st
import pandas as pd
import nltk
from nltk.chat.util import Chat, reflections

# ==========================================
# 1. CONFIGURATION DE LA PAGE STREAMLIT
# ==========================================
st.set_page_config(
    page_title="CyberLog Chatbot - Security Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Injection de style CSS (Thème Sombre Cybersécurité)
st.markdown("""
<style>
    .stApp { background-color: #0b0f19; color: #e2e8f0; }
    .main-title { color: #00f2fe; font-size: 2.2rem; font-weight: 700; margin-bottom: 0px; }
    .sub-title { color: #94a3b8; font-size: 0.95rem; margin-bottom: 20px; }
    .alert-box { background-color: #2e1065; border: 1px solid #7c3aed; border-radius: 8px; padding: 12px; margin-top: 10px; }
    .chat-user { background-color: #1e293b; padding: 8px 12px; border-radius: 10px 10px 0px 10px; margin-bottom: 6px; color: #38bdf8; font-size: 0.9rem; }
    .chat-bot { background-color: #0f172a; padding: 8px 12px; border-radius: 10px 10px 10px 0px; margin-bottom: 10px; border: 1px solid #334155; font-size: 0.9rem; }
</style>
""", unsafe_allow_html=True)


# ==========================================
# 2. PAGE D'AUTHENTIFICATION
# ==========================================
if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False

def login_page():
    st.markdown("<br><br>", unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1, 1.5, 1])
    with col2:
        st.markdown("<h1 style='text-align: center; color: #00f2fe;'>🛡️ CyberLog SOC</h1>", unsafe_allow_html=True)
        st.markdown("<p style='text-align: center; color: #94a3b8;'>Plateforme de Détection Brute Force</p>", unsafe_allow_html=True)
        with st.form("login_form"):
            username = st.text_input("Nom d'utilisateur", placeholder="admin")
            password = st.text_input("Mot de passe", type="password", placeholder="••••••••")
            submit_button = st.form_submit_button("Se connecter 🔓", use_container_width=True)
            if submit_button:
                if username == "admin" and password == "cyber123":
                    st.session_state["logged_in"] = True
                    st.rerun()
                else:
                    st.error("Identifiants incorrects (Demo: admin / cyber123)")

if not st.session_state["logged_in"]:
    login_page()
    st.stop()


# ==========================================
# 3. PAIRES DE DIALOGUE NLTK
# ==========================================
pairs = [
    [r"Bonjour|salut|coucou|hello", ["Bonjour ! Je suis l'assistant CyberSecurity. Comment puis-je vous aider ?"]],
    
    # Définition Brute Force
    [r"(?i).*(qu'est-ce qu'une|définition|c'est quoi).*(force brute|brute force).*",
     ["Une attaque Brute Force consiste à tester automatiquement des milliers de combinaisons de mots de passe. Elle se caractérise par un nombre anormalement élevé d'échecs de connexion sur un serveur."]],

    # Types d'attaques
    [r"(?i).*(types|sortes|catégories) d'attaque.*",
     ["Variantes principales :\n- Brute force simple\n- Attaque par dictionnaire\n- Credential stuffing\n- Reverse brute force."]],

    # Conseils généraux de sécurité
    [r"(?i).*(conseil|recommandation|que faire|protéger|sécuriser).*",
     ["💡 **Conseils de sécurité recommandés :**\n"
      "1. **Blocage d'IP** : Verrouiller les adresses IP après 3 échecs consécutifs.\n"
      "2. **Authentification Forte** : Activer le 2FA (Double facteur).\n"
      "3. **Mots de passe** : Imposer une longueur minimale de 12 caractères avec des symboles."]],

    # Détection
    [r"(?i).*(comment|peut-on) détecter.*",
     ["La détection repose sur l'analyse des logs : présence d'un grand nombre de statuts `FAILED` ciblant un même serveur en peu de temps."]],

    # Fallback
    [r"(?i).*", ["Je suis à votre disposition. Posez-moi des questions sur les attaques Brute Force ou demandez des conseils d'analyse sur vos logs."]]
]

chat = Chat(pairs, reflections)


# ==========================================
# 4. REPONSE DYNAMIQUE DU CHATBOT (AVEC LOGS PANDAS)
# ==========================================
def dynamic_chatbot_response(user_query, analysis_results):
    query = user_query.lower()
    
    # Détection d'attaque dans les logs
    if any(k in query for k in ["attaque", "brute force", "danger", "suspect", "menace"]):
        if analysis_results["suspicious_count"] > 0:
            return f"⚠️ **Alerte Détectée** : Activité suspecte assimilée à du Brute Force ! **{analysis_results['suspicious_count']} IP suspecte(s)** ont franchi le seuil d'échecs."
        return "✅ **Sécurité Normale** : Aucune attaque par force brute n'a été identifiée dans le fichier actuel."

    # Identification des IP suspectes
    elif any(k in query for k in ["quelle ip", "ip suspecte", "adresse ip", "qui est l'attaquant"]):
        if analysis_results["suspicious_count"] > 0:
            details = [f"- **{ip}** avec **{count} tentatives échouées**" for ip, count in analysis_results["suspicious_ips"].items()]
            return "⚠️ **Adresse(s) IP suspecte(s) actuellement identifiée(s) :**\n" + "\n".join(details)
        return "Aucune adresse IP n'est actuellement identifiée comme suspecte."

    # Conseils personnalisés selon les données réelles
    elif any(k in query for k in ["conseil", "solution", "que faire", "recommandation"]):
        if analysis_results["suspicious_count"] > 0:
            return (
                "🛡️ **Recommandations d'urgence pour vos logs :**\n"
                "1. **Bloquer les IP suspectes** sur votre pare-feu.\n"
                "2. **Réinitialiser le mot de passe** des comptes visés par les tentatives d'accès.\n"
                "3. **Activer un CAPTCHA** sur le formulaire de connexion."
            )
        return "💡 **Conseil de prévention :** Le système est actuellement stable. Maintenez une surveillance régulière de vos journaux d'accès."

    # Statistiques globales
    elif any(k in query for k in ["combien", "statistique", "nombre", "échec", "tentative"]):
        return f"📊 **Résumé des logs :**\n- Connexions réussies : **{analysis_results['success_total']}**\n- Connexions échouées : **{analysis_results['failed_total']}**\n- Total d'événements : **{analysis_results['total_logs']}**"

    # NLTK par défaut
    return chat.respond(user_query)


# ==========================================
# 5. SIDEBAR & CHARGEMENT DE DONNEES
# ==========================================
with st.sidebar:
    st.title("🛡️ CyberLog Panel")
    st.write("---")
    uploaded_file = st.file_uploader("Importer un fichier CSV de logs", type=["csv"])
    st.write("---")
    threshold = st.slider("Seuil d'échecs (Brute Force)", min_value=2, max_value=10, value=3)
    st.write("---")
    if st.button("Se déconnecter 🚪", use_container_width=True):
        st.session_state["logged_in"] = False
        st.rerun()

# Données importées ou exemple
if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)
else:
    df = pd.DataFrame({
        "timestamp": ["2026-09-19 10:00", "2026-09-19 10:01", "2026-09-19 10:02", "2026-09-19 10:03", "2026-09-19 10:04"],
        "ip": ["192.168.1.10", "192.168.1.20", "192.168.1.20", "192.168.1.20", "192.168.1.20"],
        "username": ["admin", "root", "root", "admin", "administrator"],
        "status": ["SUCCESS", "FAILED", "FAILED", "FAILED", "FAILED"]
    })

# Normalisation des colonnes
df.columns = [c.lower() for c in df.columns]

# Calculs Pandas
total_logs = len(df)
success_total = len(df[df["status"].str.upper() == "SUCCESS"])
failed_df = df[df["status"].str.upper() == "FAILED"]
failed_total = len(failed_df)
failed_by_ip = failed_df["ip"].value_counts() if not failed_df.empty else pd.Series(dtype=int)
suspicious_ips = failed_by_ip[failed_by_ip >= threshold]
suspicious_count = len(suspicious_ips)

analysis_results = {
    "total_logs": total_logs,
    "success_total": success_total,
    "failed_total": failed_total,
    "suspicious_count": suspicious_count,
    "suspicious_ips": suspicious_ips.to_dict()
}


# ==========================================
# 6. INTERFACE PRINCIPALE (DASHBOARD + CHATBOT)
# ==========================================
st.markdown('<p class="main-title">🛡️ CyberLog Security Dashboard</p>', unsafe_allow_html=True)
st.markdown('<p class="sub-title">Analyse en temps réel et assistant conversationnel de sécurité</p>', unsafe_allow_html=True)

# Alignement côte à côte (Dashboard à gauche, Chatbot à droite)
col_dash, col_chat = st.columns([1.5, 1])

with col_dash:
    # Cartes de métriques
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Logs", total_logs)
    m2.metric("Réussies", success_total)
    m3.metric("Échouées", failed_total)
    m4.metric("IP Suspectes", suspicious_count)

    st.write("---")
    st.subheader("🔍 Aperçu des Logs de Connexion")
    st.dataframe(df, use_container_width=True, height=220)

    # Zone d'alerte en cas d'attaque
    if suspicious_count > 0:
        st.error(f"⚠️ Activité Suspecte Détectée ({suspicious_count} adresse(s) IP dépasse(nt) le seuil de {threshold} échecs)")
        for ip, count in suspicious_ips.items():
            st.markdown(f"""
            <div class="alert-box">
                <b style="color:#ef4444;">⚠️ Attaque Brute Force Possible</b><br>
                <b>IP concernée :</b> <code>{ip}</code> | <b>Échecs :</b> <span style="color:#f87171;">{count}</span>
            </div>
            """, unsafe_allow_html=True)

with col_chat:
    st.subheader("💬 Assistant CyberBot")
    
    # Initialisation de l'historique du chat
    if "chat_history" not in st.session_state:
        st.session_state["chat_history"] = [
            {"role": "assistant", "content": "Bonjour ! Posez-moi des questions sur vos logs ou demandez-moi des conseils de sécurité."}
        ]

    # Conteneur de discussion fixe avec scroll
    chat_box = st.container(height=340)
    with chat_box:
        for msg in st.session_state["chat_history"]:
            if msg["role"] == "user":
                st.markdown(f'<div class="chat-user"><b>Vous :</b> {msg["content"]}</div>', unsafe_allow_html=True)
            else:
                st.markdown(f'<div class="chat-bot"><b>🤖 Bot :</b> {msg["content"]}</div>', unsafe_allow_html=True)

    # Champ de saisie utilisateur
    with st.form("chat_form", clear_on_submit=True):
        user_input = st.text_input("Votre message :", placeholder="Ex: Quelle IP est suspecte ? ou Donne moi des conseils")
        send_button = st.form_submit_button("Envoyer 📩", use_container_width=True)

    if send_button and user_input:
        st.session_state["chat_history"].append({"role": "user", "content": user_input})
        response = dynamic_chatbot_response(user_input, analysis_results)
        st.session_state["chat_history"].append({"role": "assistant", "content": response})
        st.rerun()