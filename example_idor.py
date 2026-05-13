from flask import Flask, request, jsonify

app = Flask(__name__)

# Simulated database of user data
user_data = {
    '1': {'name': 'Alice', 'balance': 5000},
    '2': {'name': 'Bob', 'balance': 3000},
    '3': {'name': 'Charlie', 'balance': 7000},
}

@app.route('/balance', methods=['GET'])
def get_balance():
    # rule-id: my_first_idor_rule
    user_id = request.args.get('user_id')
    if user_id in user_data:
        return jsonify(user_data[user_id])
    else:
        return jsonify({'error': 'User not found'}), 404


def get_balance2():
    # ok: my_first_idor_rule
    user_id = request.args.get('user_id')
    if user_id in user_data:
        return jsonify(user_data[user_id])
    else:
        return jsonify({'error': 'User not found'}), 404

if __name__ == '__main__':
    app.run(debug=True)

