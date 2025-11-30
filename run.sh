# run.sh

# create virtual env
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

source venv/bin/activate

# install dependencies
echo "Installing dependencies..."
sudo apt update
sudo apt install graphviz

# run the query optimizer
echo "Running the optimizer..."
python3 src/main.py $1 