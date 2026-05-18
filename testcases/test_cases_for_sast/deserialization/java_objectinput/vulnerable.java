ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
Object obj = ois.readObject();
