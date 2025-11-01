# run.sh

# install dependencies
pip install -r requirements.txt

# run the query optimizer
python3 heuristic_query_optimizer.py $1 