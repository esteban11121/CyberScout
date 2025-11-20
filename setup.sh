#!/usr/bin/env bash
set -e

echo "📦 Creando entorno virtual..."
python3 -m venv venv
source venv/bin/activate

echo "⬆️ Actualizando pip..."
pip install --upgrade pip

echo "📚 Instalando dependencias..."
pip install -r requirements.txt

if [ ! -f ".env" ]; then
  echo "🧾 Creando archivo .env..."
  cat > .env << 'EOF'
TELEGRAM_BOT_TOKEN=CAMBIAR_POR_TU_TOKEN
VT_API_KEY=CAMBIAR_POR_TU_API_KEY_DE_VIRUSTOTAL
ABUSEIPDB_API_KEY=CAMBIAR_POR_TU_API_KEY_DE_ABUSEIPDB
EOF
fi

echo "⚠️ Recordá editar .env antes de usar el bot."
echo "Para ejecutar: source venv/bin/activate && python CyberScout.py"