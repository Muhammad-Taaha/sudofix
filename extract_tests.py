import os
from controllers.reddis_controller import RedisManager


def extract_all_tests():
    redis_mgr = RedisManager(redis_db=1)
    client = redis_mgr.connect()

    if not client:
        return

    output_dir = "extracted_tests"
    os.makedirs(output_dir, exist_ok=True)

    keys = client.keys('*')
    print(f"📂 Found {len(keys)} keys in Redis.")

    for i, key in enumerate(keys):
        # Check what kind of data is stored here
        key_type = client.type(key).decode('utf-8')

        try:
            if key_type == 'string':
                test_content = client.get(key).decode('utf-8')
            elif key_type == 'hash':
                # If it's a hash, we get all fields (maybe you stored it as a dict?)
                raw_data = client.hgetall(key)
                test_content = str(raw_data)
            else:
                print(f"⏭️ Skipping key {i} because type is {key_type}")
                continue

            file_path = os.path.join(output_dir, f"test_generated_{i}.py")
            with open(file_path, "w") as f:
                f.write(test_content)
            print(f"💾 Saved: {file_path}")

        except Exception as e:
            print(f"❌ Error processing key {i}: {e}")


if __name__ == "__main__":
    extract_all_tests()
