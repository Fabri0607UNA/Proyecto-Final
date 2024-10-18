import tkinter as tk
from tkinter import ttk  # Asegura importar ttk desde tkinter
import cx_Oracle

#prueba

# Función para conectar a Oracle
def conectar_oracle(): 
    try:
        # Credenciales y datos de conexión
        dsn_tns = cx_Oracle.makedsn('localhost', '1521', sid='xe')
        conexion = cx_Oracle.connect(user='sys', password='root', dsn=dsn_tns, mode=cx_Oracle.SYSDBA)
        print("Conexión exitosa a Oracle")
        return conexion
    except cx_Oracle.DatabaseError as e:
        print(f"Error al conectar a la base de datos: {e}")
        return None

# Función para probar la conexión
def conectar():
    conexion = conectar_oracle()
    if conexion:
        label_status.config(text="Conexión exitosa")
    else:
        label_status.config(text="Error al conectar")

# Función para ejecutar una consulta de ejemplo
def ejecutar_consulta():
    conexion = conectar_oracle()
    if conexion:
        try:
            cursor = conexion.cursor()
            cursor.execute("SELECT table_name FROM user_tables")  # Ejemplo: listar las tablas del esquema actual
            tablas = cursor.fetchall()
            print("Tablas en el esquema actual:")
            for tabla in tablas:
                print(tabla[0])
        except cx_Oracle.DatabaseError as e:
            print(f"Error ejecutando la consulta: {e}")
        finally:
            cursor.close()
            conexion.close()
    else:
        print("No se pudo conectar para ejecutar la consulta")
    
# Función placeholder para la creación de respaldos
def crear_respaldo(tipo):
    print(f"Creando respaldo {tipo}...")
    # Aquí implementarías la lógica de creación del respaldo en Oracle.

# Función para cerrar sesión
def desconectar(conexion, root):
    if conexion:
        conexion.close()
        print("Conexión cerrada")
    root.destroy()

# Función para cambiar a la ventana de pestañas después de conectar
def mostrar_pestañas(conexion):
    if conexion:
        # Cerrar ventana principal
        root.destroy()
        
        # Crear nueva ventana con las pestañas de funciones
        ventana_funciones = tk.Tk()
        ventana_funciones.title("Administrador de Base de Datos")
        ventana_funciones.geometry("600x400")
        
        # Creación de un widget de pestañas
        tabs = ttk.Notebook(ventana_funciones)

        # Pestaña para "Respaldos"
        tab_respaldos = ttk.Frame(tabs)
        tabs.add(tab_respaldos, text="Respaldos")

        # Pestaña para "Recuperación de Respaldos"
        tab_recuperacion = ttk.Frame(tabs)
        tabs.add(tab_recuperacion, text="Recuperación de Respaldos")

        # Pestaña para "Administración de Tablespaces"
        tab_tablespaces = ttk.Frame(tabs)
        tabs.add(tab_tablespaces, text="Tablespaces")

        # Pestaña para "Tunning de Consultas"
        tab_tunning = ttk.Frame(tabs)
        tabs.add(tab_tunning, text="Tunning Consultas")

        # Pestaña para "Performance"
        tab_performance = ttk.Frame(tabs)
        tabs.add(tab_performance, text="Performance")

        # Pestaña para "Auditoría"
        tab_auditoria = ttk.Frame(tabs)
        tabs.add(tab_auditoria, text="Auditoría")

        # Pestaña para "Seguridad de Usuarios"
        tab_seguridad = ttk.Frame(tabs)
        tabs.add(tab_seguridad, text="Seguridad")

        # Agregar las pestañas a la ventana
        tabs.pack(expand=1, fill="both")

        # Añadir contenido a la pestaña de "Respaldos"
        tk.Label(tab_respaldos, text="Seleccione el tipo de respaldo:").pack(pady=10)

        # Botones para cada tipo de respaldo
        btn_schema = tk.Button(tab_respaldos, text="Respaldo por Schema", command=lambda: crear_respaldo("schema"))
        btn_schema.pack(pady=5)

        btn_tabla = tk.Button(tab_respaldos, text="Respaldo por Tabla", command=lambda: crear_respaldo("tabla"))
        btn_tabla.pack(pady=5)

        btn_full = tk.Button(tab_respaldos, text="Respaldo Full", command=lambda: crear_respaldo("full"))
        btn_full.pack(pady=5)

        # Botón para cerrar sesión o desconectar
        btn_desconectar = tk.Button(ventana_funciones, text="Cerrar Sesión", command=lambda: desconectar(conexion, ventana_funciones))
        btn_desconectar.pack(pady=20)

        ventana_funciones.mainloop()

# Función para manejar la conexión desde el botón
def conectar():
    global conexion
    conexion = conectar_oracle()
    if conexion:
        label_status.config(text="Estado: Conexión exitosa", fg="green")
        root.after(2000, lambda: mostrar_pestañas(conexion))  # Cambiar a la ventana de pestañas después de 2 segundos
    else:
        label_status.config(text="Estado: Error al conectar", fg="red")

# Ventana principal para la conexión
root = tk.Tk()
root.title("Conexión a Oracle")
root.geometry("400x200")

# Botón para conectar a Oracle
btn_conectar = tk.Button(root, text="Conectar a Oracle", command=conectar)
btn_conectar.pack(pady=10)

# Label para mostrar el estado de la conexión
label_status = tk.Label(root, text="Estado: Desconectado", fg="blue")
label_status.pack(pady=5)

root.mainloop()