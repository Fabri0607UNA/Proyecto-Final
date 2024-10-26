import cx_Oracle
import tkinter as tk
from tkinter import ttk  # Asegura importar ttk desde tkinter
from tkinter import messagebox
from tkinter import simpledialog, scrolledtext
import subprocess
import threading


class Controlador:
    def __init__(self):
        self.URL = cx_Oracle.makedsn('localhost', '1521', sid='xe')
        self.conector = None

    def get_conexion(self, user, password):
        try:
            if user.lower() in ["sys", "system"]:
                user = "sys as sysdba"
            
            self.conector = cx_Oracle.connect(user=user, password=password, dsn=self.URL, mode=cx_Oracle.SYSDBA)
            return True
        except cx_Oracle.Error as e:
            print(f"Error de conexión: {e}")
            return False

    def cargar_usuario(self):
        query = "SELECT USERNAME FROM DBA_USERS"
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            return cursor
        except cx_Oracle.Error as e:
            print(f"Error al cargar usuarios: {e}")
            return None

    def cargar_total_privilegios(self):
        query = "select * from session_privs"
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            return cursor
        except cx_Oracle.Error as e:
            print(f"Error al cargar privilegios: {e}")
            return None

    def cargar_total_roles(self):
        query = "SELECT role FROM dba_roles"
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            return cursor
        except cx_Oracle.Error as e:
            print(f"Error al cargar roles: {e}")
            return None

    def revocar_privilegios_rol(self, rol, priv):
        query = f"revoke {priv} from {rol}"
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            self.conector.commit()
            return True
        except cx_Oracle.Error as e:
            print(f"Error al revocar privilegios: {e}")
            return False

    def otorgar_privilegios_rol(self, rol, priv):
        query = f"GRANT {priv} TO {rol}"
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            self.conector.commit()
            return True
        except cx_Oracle.Error as e:
            print(f"Error al otorgar privilegios: {e}")
            return False


    def cargar_sesiones_bd(self):
        query = """
        SELECT s.sid, s.serial#, s.username, s.program 
        FROM gv$session s 
        JOIN gv$process p ON p.addr = s.paddr AND p.inst_id = s.inst_id 
        WHERE s.type != 'BACKGROUND'
        """
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            return cursor
        except cx_Oracle.Error as e:
            print(f"Error al cargar sesiones: {e}")
            return None

    def cerrar_sesion_bd(self, sid, serial, band):
        query = f"ALTER SYSTEM {'KILL' if band == 1 else 'DISCONNECT'} SESSION '{sid},{serial}' IMMEDIATE"
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            self.conector.commit()
            return True
        except cx_Oracle.Error as e:
            print(f"Error al cerrar sesión: {e}")
            return False

    def cargar_directorios(self):
        query = "SELECT NAME, PATH FROM datapump_dir_objs"
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            return cursor
        except cx_Oracle.Error as e:
            print(f"Error al cargar directorios: {e}")
            return None

    def cargar_tablas_usuario(self, usuario):
        query = f"SELECT table_name FROM all_tables WHERE owner = '{usuario}'"
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            return cursor
        except cx_Oracle.Error as e:
            print(f"Error al cargar tablas del usuario: {e}")
            return None

    def crear_directorio(self, nombre_dir, path_dir, user):
        try:
            cursor = self.conector.cursor()
            cursor.execute(f"CREATE OR REPLACE DIRECTORY {nombre_dir} AS '{path_dir}'")
            cursor.execute(f"GRANT WRITE, READ ON DIRECTORY {nombre_dir} TO {user}")
            self.conector.commit()
            return True
        except cx_Oracle.Error as e:
            print(f"Error al crear directorio: {e}")
            return False

    def eliminar_directorio(self, nombre_dir):
        try:
            cursor = self.conector.cursor()
            cursor.execute(f"DROP DIRECTORY {nombre_dir}")
            self.conector.commit()
            return True
        except cx_Oracle.Error as e:
            print(f"Error al eliminar directorio: {e}")
            return False

    def cargar_columnas_user(self, usuario, tabla):
        query = f"SELECT COLUMN_NAME FROM ALL_TAB_COLUMNS WHERE owner = '{usuario}' AND TABLE_NAME = '{tabla}'"
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            return cursor
        except cx_Oracle.Error as e:
            print(f"Error al cargar columnas: {e}")
            return None

    def cargar_pk_fk_key_tabla(self, tabla):
        query = f"""
        SELECT cols.column_name, cons.constraint_name, cons.constraint_type
        FROM all_constraints cons, all_cons_columns cols
        WHERE cols.table_name = '{tabla}'
        AND NOT cons.constraint_type = 'C'
        AND cons.constraint_name = cols.constraint_name
        AND cons.owner = cols.owner
        """
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            return cursor
        except cx_Oracle.Error as e:
            print(f"Error al cargar PK/FK: {e}")
            return None

    def cargar_indices_tabla(self, tabla):
        query = f"""
        SELECT c.index_name, c.column_name 
        FROM all_indexes i 
        JOIN ALL_ind_columns c ON i.index_name = c.index_name 
        WHERE i.table_name = '{tabla}'
        """
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            return cursor
        except cx_Oracle.Error as e:
            print(f"Error al cargar índices: {e}")
            return None

    def eliminar_indice(self, nom_indice):
        try:
            cursor = self.conector.cursor()
            cursor.execute(f"DROP INDEX {nom_indice}")
            self.conector.commit()
            return True
        except cx_Oracle.Error as e:
            print(f"Error al eliminar índice: {e}")
            return False

    def crear_pk(self, tabla, col, nom_pk):
        query = f"ALTER TABLE {tabla} ADD CONSTRAINT {nom_pk} PRIMARY KEY ({col})"
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            self.conector.commit()
            return True
        except cx_Oracle.Error as e:
            print(f"Error al crear PK: {e}")
            return False

    def eliminar_pk(self, tabla, nom_pk):
        query = f"ALTER TABLE {tabla} DROP CONSTRAINT {nom_pk}"
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            self.conector.commit()
            return True
        except cx_Oracle.Error as e:
            print(f"Error al eliminar PK: {e}")
            return False

    def cargar_info_tabla(self, usuario, tabla):
        query = f"""
        SELECT column_name, data_type 
        FROM ALL_TAB_COLUMNS 
        WHERE owner = '{usuario}' AND TABLE_NAME = '{tabla}'
        """
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            return cursor
        except cx_Oracle.Error as e:
            print(f"Error al cargar info de tabla: {e}")
            return None

    def eliminar_tabla(self, tabla):
        try:
            cursor = self.conector.cursor()
            cursor.execute(f"DROP TABLE {tabla}")
            self.conector.commit()
            return True
        except cx_Oracle.Error as e:
            print(f"Error al eliminar tabla: {e}")
            return False

    def ejecutar_codigo(self, cadena):
        try:
            cursor = self.conector.cursor()
            cursor.execute(cadena)
            self.conector.commit()
            return True
        except cx_Oracle.Error as e:
            print(f"Error al ejecutar código: {e}")
            return False

    def create_table(self, nomb_table, cadena):
        query = f"CREATE TABLE {nomb_table}({cadena})"
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            self.conector.commit()
            return True
        except cx_Oracle.Error as e:
            print(f"Error al crear tabla: {e}")
            return False

    def genera_stats(self, usuario, tabla):
        try:
            cursor = self.conector.cursor()
            if tabla == "Schema":
                tablas = self.cargar_tablas_usuario(usuario)
                for row in tablas:
                    query = f"ANALYZE TABLE {usuario}.{row[0]} COMPUTE STATISTICS"
                    cursor.execute(query)
            else:
                query = f"ANALYZE TABLE {usuario}.{tabla} COMPUTE STATISTICS"
                cursor.execute(query)
            self.conector.commit()
            tk.messagebox.showinfo("Éxito", "Estadística realizada con éxito!")
            return True
        except cx_Oracle.Error as e:
            print(f"Error al generar estadísticas: {e}")
            return False
        
    def consulta_stats(self, tabla):
        query = f"""
        SELECT OWNER, TABLE_NAME, NUM_ROWS, LAST_ANALYZED 
        FROM DBA_TABLES 
        WHERE {"TABLE_NAME='" + tabla + "'" if tabla != 'Schema' else ''}
        """
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            return cursor
        except cx_Oracle.Error as e:
            print(f"Error en consulta de estadísticas: {e}")
            return None

    def info_instancia(self):
        query = "SELECT * FROM v$instance"
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            return cursor
        except cx_Oracle.Error as e:
            print(f"Error al obtener info de instancia: {e}")
            return None

    def nombre_db(self):
        query = "SELECT value FROM v$system_parameter WHERE name = 'db_name'"
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            return cursor
        except cx_Oracle.Error as e:
            print(f"Error al obtener nombre de DB: {e}")
            return None

    def parametros_db(self):
        query = "SELECT * FROM v$system_parameter"
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            return cursor
        except cx_Oracle.Error as e:
            print(f"Error al obtener parámetros de DB: {e}")
            return None

    def prod_oracle(self):
        query = "SELECT * FROM product_component_version"
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            return cursor
        except cx_Oracle.Error as e:
            print(f"Error al obtener productos Oracle: {e}")
            return None

    def ip_server(self):
        query = "SELECT utl_inaddr.get_host_address IP FROM DUAL"
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            return cursor
        except cx_Oracle.Error as e:
            print(f"Error al obtener IP del servidor: {e}")
            return None

    def spfile_file(self):
        query = "SELECT value FROM v$system_parameter WHERE name = 'spfile'"
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            return cursor
        except cx_Oracle.Error as e:
            print(f"Error al obtener SPFILE: {e}")
            return None

    def control_files(self):
        query = "SELECT value FROM v$system_parameter WHERE name = 'control_files'"
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            return cursor
        except cx_Oracle.Error as e:
            print(f"Error al obtener archivos de control: {e}")
            return None

    def all_files(self):
        query = "SELECT FILE_ID, FILE_NAME, TABLESPACE_NAME FROM DBA_DATA_FILES"
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            return cursor
        except cx_Oracle.Error as e:
            print(f"Error al obtener todos los archivos: {e}")
            return None

    def temp_files(self):
        query = "SELECT FILE#, NAME FROM V$TEMPFILE"
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            return cursor
        except cx_Oracle.Error as e:
            print(f"Error al obtener archivos temporales: {e}")
            return None

    def redo_log_files(self):
        query = "SELECT member FROM v$logfile"
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            return cursor
        except cx_Oracle.Error as e:
            print(f"Error al obtener archivos de redo log: {e}")
            return None

    def tam_tablespaces(self):
        query = """
        SELECT t.tablespace_name "Tablespace",
               t.status "Estado",
               ROUND(MAX(d.bytes) / 1024 / 1024, 2) "MB Tamaño",
               ROUND((MAX(d.bytes) / 1024 / 1024) - (SUM(DECODE(f.bytes, NULL, 0, f.bytes)) / 1024 / 1024), 2) "MB Usados",
               ROUND(SUM(DECODE(f.bytes, NULL, 0, f.bytes)) / 1024 / 1024, 2) "MB Libres",
               t.pct_increase "% incremento",
               SUBSTR(d.file_name, 1, 80) "Fichero de datos"
        FROM DBA_FREE_SPACE f, DBA_DATA_FILES d, DBA_TABLESPACES t
        WHERE t.tablespace_name = d.tablespace_name
        AND f.tablespace_name(+) = d.tablespace_name
        AND f.file_id(+) = d.file_id
        GROUP BY t.tablespace_name, d.file_name, t.pct_increase, t.status
        ORDER BY 1, 3 DESC
        """
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            return cursor
        except cx_Oracle.Error as e:
            print(f"Error al obtener tamaño de tablespaces: {e}")
            return None


    def tam_bd(self):
        query = "SELECT SUM(BYTES)/1024/1024 AS MB FROM DBA_EXTENTS"
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            result = cursor.fetchone()  # Obtener el primer resultado
            return result  # Retornar el resultado en lugar del cursor
        except cx_Oracle.Error as e:
            print(f"Error al obtener tamaño de BD: {e}")
            return None


    def tam_files_bd(self):
        query = "SELECT SUM(bytes)/1024/1024 MB FROM dba_data_files"
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            return cursor
        except cx_Oracle.Error as e:
            print(f"Error al obtener tamaño de archivos de BD: {e}")
            return None

    def tam_objs(self):
        query = """
        SELECT SEGMENT_NAME, SUM(BYTES)/1024/1024 MB 
        FROM DBA_EXTENTS 
        GROUP BY SEGMENT_NAME 
        ORDER BY 2 DESC
        """
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            return cursor
        except cx_Oracle.Error as e:
            print(f"Error al obtener tamaño de objetos: {e}")
            return None

    def obj_owner(self):
        query = """
        SELECT owner, COUNT(owner) Numero 
        FROM dba_objects 
        GROUP BY owner 
        ORDER BY Numero DESC
        """
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            return cursor
        except cx_Oracle.Error as e:
            print(f"Error al obtener propietarios de objetos: {e}")
            return None

    def info_tablespaces(self):
        query = "SELECT * FROM V$TABLESPACE"
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            return cursor
        except cx_Oracle.Error as e:
            print(f"Error al obtener info de tablespaces: {e}")
            return None

    def borrar_tabla_planes(self):
        try:
            cursor = self.conector.cursor()
            cursor.execute("DELETE PLAN_TABLE")
            self.conector.commit()
            return True
        except cx_Oracle.Error as e:
            print(f"Error al borrar tabla de planes: {e}")
            return False

    def executar_query_optimizar(self, query):
        try:
            cursor = self.conector.cursor()
            cursor.execute(f"EXPLAIN PLAN FOR {query}")
            self.conector.commit()
            return "true"
        except cx_Oracle.Error as e:
            return str(e)

    def obtener_explain_plan(self):
        query = """
        SELECT SUBSTR(LPAD(' ', LEVEL-1) || OPERATION || ' (' || OPTIONS|| ')', 1, 30) AS OPERACION,
               OBJECT_NAME AS OBJETO, TIMESTAMP AS FECHA
        FROM PLAN_TABLE
        START WITH ID = 0
        CONNECT BY PRIOR ID=PARENT_ID
        """
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            plan = cursor.fetchall()  # Obtén todas las filas como lista de tuplas
            cursor.close()
            return plan
        except cx_Oracle.Error as e:
            print(f"Error al obtener explain plan: {e}")
            return None

    def crear_rol(self, rol):
        try:
            cursor = self.conector.cursor()
            cursor.execute("ALTER SESSION SET \"_ORACLE_SCRIPT\"=TRUE")
            cursor.execute(f"CREATE ROLE {rol}")
            self.conector.commit()
            return True
        except cx_Oracle.Error as e:
            print(f"Error al crear rol: {e}")
            return False

    def crear_usuario(self, usuario):
        try:
            cursor = self.conector.cursor()
            cursor.execute("ALTER SESSION SET \"_ORACLE_SCRIPT\"=TRUE")
            cursor.execute(f"CREATE USER {usuario}")
            self.conector.commit()
            return True
        except cx_Oracle.Error as e:
            print(f"Error al crear usuario: {e}")
            return False

    def cargar_roles(self, usuario):
        query = f"SELECT GRANTED_ROLE FROM DBA_ROLE_PRIVS WHERE GRANTEE='{usuario}'"
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            return cursor
        except cx_Oracle.Error as e:
            print(f"Error al cargar roles: {e}")
            return None

    def revocar_rol_usuario(self, rol, user):
        try:
            cursor = self.conector.cursor()
            cursor.execute(f"REVOKE {rol} FROM {user}")
            self.conector.commit()
            return True
        except cx_Oracle.Error as e:
            print(f"Error al revocar rol: {e}")
            return False

    def otorgar_rol_usuario(self, rol, user):
        try:
            cursor = self.conector.cursor()
            cursor.execute(f"GRANT {rol} TO {user}")
            self.conector.commit()
            return True
        except cx_Oracle.Error as e:
            print(f"Error al otorgar rol: {e}")
            return False

    # Métodos de auditoría
    def auditar_conexiones(self):
        return self._ejecutar_auditoria("AUDIT CONNECT")

    def auditar_inicios_sesion(self):
        return self._ejecutar_auditoria("AUDIT SESSION")

    def auditar_inicios_sesion_exitosos(self):
        return self._ejecutar_auditoria("AUDIT SESSION WHENEVER SUCCESSFUL")

    def auditar_inicios_sesion_no_exitosos(self):
        return self._ejecutar_auditoria("AUDIT SESSION WHENEVER NOT SUCCESSFUL")

    def auditar_de_accion(self):
        return self._ejecutar_auditoria("AUDIT ROLE")

    def auditar_tabla(self, schema, tabla):
        return self._ejecutar_auditoria(f"AUDIT INSERT, UPDATE, DELETE, SELECT ON {schema}.{tabla} BY ACCESS")

    def _ejecutar_auditoria(self, query):
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            self.conector.commit()
            return True
        except cx_Oracle.Error as e:
            print(f"Error en auditoría: {e}")
            return False

    def ver_auditoria_por_accion(self):
        query = """
        SELECT sessionid, userhost, username, action_name, obj_name, action 
        FROM sys.dba_audit_trail 
        WHERE action_name IN ('INSERT', 'UPDATE', 'DELETE', 'SELECT')
        """
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            return cursor
        except cx_Oracle.Error as e:
            print(f"Error al ver auditoría por acción: {e}")
            return None

    def visualizar_auditoria_sesiones(self):
        query = """
        SELECT Username, 
               DECODE(Returncode, '0', 'Conectado', '1005', 'Fallo - Null', '1017', 'Fallo', Returncode) Tipo_Suceso,
               TO_CHAR(Timestamp, 'DD-MM-YY HH24:MI:SS') Hora_Inicio_Sesion, 
               TO_CHAR(Logoff_Time, 'DD-MM-YY HH24:MI:SS') Hora_Fin_Sesion 
        FROM DBA_AUDIT_SESSION
        """
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            return cursor
        except cx_Oracle.Error as e:
            print(f"Error al visualizar auditoría de sesiones: {e}")
            return None

    def ver_tablas_x_schema(self, schema):
        query = f"SELECT table_name FROM all_tables WHERE owner = '{schema}' ORDER BY table_name"
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            return cursor
        except cx_Oracle.Error as e:
            print(f"Error al ver tablas por schema: {e}")
            return None

    def ver_campos_x_tabla(self, tabla):
        query = f"SELECT column_name FROM all_tab_columns WHERE table_name = '{tabla}'"
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            return cursor
        except cx_Oracle.Error as e:
            print(f"Error al ver campos por tabla: {e}")
            return None

    def crear_indice(self, schema, tabla, col, nom_indice):
        query = f"CREATE INDEX {nom_indice} ON {schema}.{tabla}({col})"
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            self.conector.commit()
            return True
        except cx_Oracle.Error as e:
            print(f"Error al crear índice: {e}")
            return False
    
    def borrar_tablespace(self, nombre_tablespace):
        query = f"DROP TABLESPACE {nombre_tablespace} INCLUDING CONTENTS AND DATAFILES"
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            self.conector.commit()
            print(f"Tablespace '{nombre_tablespace}' ha sido eliminado con éxito.")
            return True
        except cx_Oracle.Error as e:
            print(f"Error al borrar el tablespace: {e}")
            return False

class OracleDBManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Administrador de Base de Datos Oracle")
        self.root.geometry("800x600")
        
        self.controlador = Controlador()
        
        self.create_login_frame()

    def create_login_frame(self):
        self.login_frame = ttk.Frame(self.root, padding="20")
        self.login_frame.place(relx=0.5, rely=0.4, anchor="center")

        title_label = ttk.Label(self.login_frame, text="Iniciar Sesión", font=("Tahoma", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 15), padx=(24, 0))

        ttk.Label(self.login_frame, text="Usuario:", font=("Tahoma", 12)).grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.username_entry = ttk.Entry(self.login_frame)
        self.username_entry.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(self.login_frame, text="Contraseña:", font=("Tahoma", 12)).grid(row=2, column=0, padx=5, pady=5, sticky="e")
        self.password_entry = ttk.Entry(self.login_frame, show="*")
        self.password_entry.grid(row=2, column=1, padx=5, pady=5)

        style = ttk.Style()
        style.configure("TButton", font=("Tahoma", 10))

        ttk.Button(self.login_frame, text="Conectar", command=self.connect, width=15, style="TButton").grid(row=3, column=0, columnspan=2, pady=15, padx=(15,0))

        self.status_label = ttk.Label(self.login_frame, text="Estado: Desconectado", foreground="red", font=("Tahoma", 10))
        self.status_label.grid(row=4, column=0, columnspan=2, padx=(12,0))

    def connect(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error de Conexión", "Por favor ingrese un usuario y una contraseña.")
            return 

        if self.controlador.get_conexion(username, password):
            self.status_label.config(text="Estado: Conectado", foreground="green")
            self.login_frame.destroy()
            self.create_main_interface()
        else:
            messagebox.showerror("Error de Conexión", "No se pudo conectar a la base de datos.")

    def create_main_interface(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill="both")

        self.create_user_management_tab()
        self.create_session_management_tab()
        self.create_tablespace_management_tab()
        self.create_backup_tab()
        self.create_query_optimization_tab()
        self.create_auditing_tab()
        self.create_database_info_tab()

        ttk.Button(self.root, text="Desconectar", command=self.disconnect).pack(pady=10)

    def create_user_management_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Gestión de Usuarios")

        ttk.Button(tab, text="Crear Usuario", command=self.create_user).pack(pady=5)
        ttk.Button(tab, text="Crear Rol", command=self.create_role).pack(pady=5)
        ttk.Button(tab, text="Otorgar Rol a Usuario", command=self.grant_role_to_user).pack(pady=5)
        ttk.Button(tab, text="Revocar Rol de Usuario", command=self.revoke_role_from_user).pack(pady=5)
        ttk.Button(tab, text="Ver Roles de Usuario", command=self.view_user_roles).pack(pady=5)

    def create_session_management_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Gestión de Sesiones")

        ttk.Button(tab, text="Ver Sesiones Activas", command=self.view_active_sessions).pack(pady=5)
        ttk.Button(tab, text="Terminar Sesión", command=self.kill_session).pack(pady=5)

    def create_tablespace_management_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Gestión de Tablespaces")

        ttk.Button(tab, text="Ver Tablespaces", command=self.view_tablespaces).pack(pady=5)
        ttk.Button(tab, text="Crear Tablespace", command=self.create_tablespace).pack(pady=5)
        ttk.Button(tab, text="Eliminar Tablespace", command=self.drop_tablespace).pack(pady=5)

    def create_backup_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Respaldo y Recuperación")

        ttk.Button(tab, text="Respaldo de Esquema", command=lambda: self.backup("schema")).pack(pady=5)
        ttk.Button(tab, text="Respaldo de Tabla", command=lambda: self.backup("table")).pack(pady=5)
        ttk.Button(tab, text="Respaldo Completo", command=lambda: self.backup("full")).pack(pady=5)
        ttk.Button(tab, text="Restaurar Respaldo", command=self.restore_backup).pack(pady=5)
        
    def create_query_optimization_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Optimización de Consultas")

        ttk.Button(tab, text="Analizar Consulta", command=self.analyze_query).pack(pady=5)
        ttk.Button(tab, text="Ver Plan de Ejecución", command=self.view_execution_plan).pack(pady=5)
        ttk.Button(tab, text="Generar Estadísticas de Tabla", command=self.generate_table_statistics).pack(pady=5)

    def create_auditing_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Auditoría")

        ttk.Button(tab, text="Habilitar Auditoría de Conexiones", command=self.controlador.auditar_conexiones).pack(pady=5)
        ttk.Button(tab, text="Habilitar Auditoría de Sesiones", command=self.controlador.auditar_inicios_sesion).pack(pady=5)
        ttk.Button(tab, text="Ver Registro de Auditoría", command=self.view_audit_trail).pack(pady=5)

    def create_database_info_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Información de la Base de Datos")

        ttk.Button(tab, text="Ver Información de la Instancia", command=self.view_instance_info).pack(pady=5)
        ttk.Button(tab, text="Ver Tamaño de la Base de Datos", command=self.view_database_size).pack(pady=5)
        ttk.Button(tab, text="Ver Archivos de Datos", command=self.view_data_files).pack(pady=5)

    # User Management Methods
    def create_user(self):
        username = simpledialog.askstring("Crear Usuario", "Ingrese el nuevo nombre de usuario:")
        if username and self.controlador.crear_usuario(username):
            messagebox.showinfo("Éxito", f"Usuario {username} creado exitosamente.")
        else:
            messagebox.showerror("Error", "No se pudo crear el usuario.")

    def create_role(self):
        role = simpledialog.askstring("Crear Rol", "Ingrese el nuevo nombre del rol:")
        if role and self.controlador.crear_rol(role):
            messagebox.showinfo("Éxito", f"Rol {role} creado exitosamente.")
        else:
            messagebox.showerror("Error", "No se pudo crear el rol.")

    def grant_role_to_user(self):
        user = simpledialog.askstring("Otorgar Rol", "Ingrese el nombre de usuario:")
        role = simpledialog.askstring("Otorgar Rol", "Ingrese el nombre del rol:")
        if user and role and self.controlador.otorgar_rol_usuario(role, user):
            messagebox.showinfo("Éxito", f"Rol {role} otorgado al usuario {user}.")
        else:
            messagebox.showerror("Error", "No se pudo otorgar el rol.")

    def revoke_role_from_user(self):
        user = simpledialog.askstring("Revocar Rol", "Ingrese el nombre de usuario:")
        role = simpledialog.askstring("Revocar Rol", "Ingrese el nombre del rol:")
        if user and role and self.controlador.revocar_rol_usuario(role, user):
            messagebox.showinfo("Éxito", f"Rol {role} revocado del usuario {user}.")
        else:
            messagebox.showerror("Error", "No se pudo revocar el rol.")

    def view_user_roles(self):
        user = simpledialog.askstring("Ver Roles", "Ingrese el nombre de usuario:")
        if user:
            roles = self.controlador.cargar_roles(user)
            if roles:
                role_list = "\n".join([row[0] for row in roles])
                messagebox.showinfo("Roles del Usuario", f"Roles para {user}:\n{role_list}")
            else:
                messagebox.showinfo("Roles del Usuario", f"No se encontraron roles para {user}")

    # Session Management Methods
    def view_active_sessions(self):
        sessions = self.controlador.cargar_sesiones_bd()
        if sessions:
            session_list = "\n".join([f"SID: {row[0]}, Serial#: {row[1]}, Usuario: {row[2]}, Programa: {row[3]}" for row in sessions])
            messagebox.showinfo("Sesiones Activas", session_list)
        else:
            messagebox.showinfo("Sesiones Activas", "No se encontraron sesiones activas")

    def kill_session(self):
        sid = simpledialog.askstring("Terminar Sesión", "Ingrese SID:")
        serial = simpledialog.askstring("Terminar Sesión", "Ingrese Serial#:")
        if sid and serial:
            if self.controlador.cerrar_sesion_bd(sid, serial, 1):
                messagebox.showinfo("Éxito", f"Sesión {sid},{serial} terminada exitosamente.")
            else:
                messagebox.showerror("Error", "No se pudo terminar la sesión.")

    # Tablespace Management Methods
    def view_tablespaces(self):
        tablespaces = self.controlador.tam_tablespaces()
        if tablespaces:
            ts_list = "\n".join([f"{row[0]}: {row[2]}MB total, {row[3]}MB usados, {row[4]}MB libres" for row in tablespaces])
            messagebox.showinfo("Tablespaces", ts_list)
        else:
            messagebox.showinfo("Tablespaces", "No se encontraron tablespaces")

    def create_tablespace(self):
        # This method would require additional implementation to create tablespaces
        messagebox.showinfo("Info", "Creación de tablespace no implementada en esta versión.")

    def drop_tablespace(self):
        nombre_tablespace = simpledialog.askstring("Eliminar Tablespace", "Ingrese el nombre del tablespace a eliminar:")

        if nombre_tablespace:
            if self.controlador.borrar_tablespace(nombre_tablespace):
                messagebox.showinfo("Éxito", f"Tablespace '{nombre_tablespace}' eliminado correctamente.")
            else:
                messagebox.showerror("Error", "No se pudo eliminar el tablespace.")

    def backup(self, backup_type):
        try:
            if backup_type == "schema":
                schema = simpledialog.askstring("Respaldo de Esquema", "Ingrese el nombre del esquema:")
                dumpfile = f'{schema}_respaldo.dmp'
                logfile = f'{schema}_respaldo.log'
                if schema:
                    result = f"expdp 'sys/root@XE as sysdba' schemas={schema} directory=respaldo dumpfile={dumpfile} logfile={logfile}"
                else:
                    messagebox.showerror("Error", "El nombre del esquema es requerido.")
                    return
            elif backup_type == "table":
                schema = simpledialog.askstring("Respaldo de Tabla", "Ingrese el nombre del esquema:")
                table = simpledialog.askstring("Respaldo de Tabla", "Ingrese el nombre de la tabla:")
                dumpfile = f'{schema}.{table}_respaldo.dmp'
                logfile = f'{schema}.{table}_respaldo.log'
                if schema and table:
                    result = f"expdp 'sys/root@XE as sysdba' tables={schema}.{table} directory=respaldo dumpfile={dumpfile} logfile={logfile}"
                else:
                    messagebox.showerror("Error", "Los nombres del esquema y la tabla son requeridos.")
                    return
            elif backup_type == "full":
                result = f"expdp 'sys/root@XE as sysdba' full=y directory=respaldo dumpfile={dumpfile} logfile={logfile}"

            # Crear una ventana nueva para mostrar la salida
            output_window = tk.Toplevel(self.root)
            output_window.title("Salida del Respaldo")
            output_text = scrolledtext.ScrolledText(output_window, width=80, height=20)
            output_text.pack(padx=10, pady=10)

            # Función para leer la salida del proceso en tiempo real
            def run_backup():
                process = subprocess.Popen(result, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                for line in iter(process.stdout.readline, ''):
                    output_text.insert(tk.END, line)
                    output_text.see(tk.END)  # Scroll hacia el final
                process.stdout.close()
                
                # Mostrar cualquier mensaje de error
                error_output = process.stderr.read()
                if error_output:
                    output_text.insert(tk.END, f"\nError:\n{error_output}")
                process.stderr.close()
                process.wait()  # Asegurarse de que el proceso haya terminado

                # Verificar si el proceso terminó sin errores
                if process.returncode == 0:
                    messagebox.showinfo("Respaldo completo", f"Respaldo {backup_type} realizado correctamente en {dumpfile}")
                else:
                    messagebox.showerror("Error", f"Error al realizar el respaldo:\n{error_output}")

            # Ejecutar el respaldo en un hilo separado para no bloquear la GUI
            threading.Thread(target=run_backup).start()

        except Exception as e:
            messagebox.showerror("Error", f"Ocurrió un error: {e}")

    def restore_backup(self):
        # Este método requeriría implementación adicional para restaurar respaldos
        messagebox.showinfo("Info", "Restauración de respaldo no implementada en esta versión.")

    # Métodos de Optimización de Consultas
    def analyze_query(self):
        query = simpledialog.askstring("Analizar Consulta", "Ingrese la consulta SQL:")
        if query:
            result = self.controlador.executar_query_optimizar(query)
            if result == "true":
                messagebox.showinfo("Éxito", "Consulta analizada exitosamente.")
            else:
                messagebox.showerror("Error", f"Error al analizar la consulta: {result}")

    def view_execution_plan(self):
        plan = self.controlador.obtener_explain_plan()
        if plan:
            plan_text = "\n".join([f"{row[0]} - {row[1]} ({row[2]})" for row in plan])
            messagebox.showinfo("Plan de Ejecución", plan_text)
        else:
            messagebox.showinfo("Plan de Ejecución", "No hay plan de ejecución disponible.")

    def generate_table_statistics(self):
        schema = simpledialog.askstring("Generar Estadísticas", "Ingrese el nombre del esquema:")
        table = simpledialog.askstring("Generar Estadísticas", "Ingrese el nombre de la tabla (o 'Schema' para todas las tablas):")
        if schema and table:
            if self.controlador.genera_stats(schema, table):
                messagebox.showinfo("Éxito", "Estadísticas generadas exitosamente.")
                stats = self.controlador.consulta_stats(table)  # Obtener los resultados de la consulta
                if stats:  # Verifica si hay resultados
                    result_message = "Estadísticas:\n"
                    for row in stats:  # Iterar sobre los resultados
                        result_message += f"Propietario: {row[0]}, Nombre de Tabla: {row[1]}, Número de Filas: {row[2]}, Último Análisis: {row[3]}\n"
                    messagebox.showinfo("Información de Estadísticas", result_message)  # Mostrar estadísticas
                else:
                    messagebox.showerror("Error", "No se encontraron estadísticas.")
            else:
                messagebox.showerror("Error", "Error al generar estadísticas.")

    # Métodos de Auditoría
    def view_audit_trail(self):
        audit_trail = self.controlador.ver_auditoria_por_accion()
        sesiones = self.controlador.visualizar_auditoria_sesiones()  # Obtener auditoría de sesiones

        trail_text = ""

        # Procesar la auditoría de acciones
        if audit_trail:
            trail_text += "\nAcciones:\n" + "\n".join([f"{row[0]} - {row[1]} - {row[2]} - {row[3]} en {row[4]}" for row in audit_trail]) + "\n"
        else:
            trail_text += "No hay auditoría disponible para acciones.\n"

        # Procesar la auditoría de sesiones
        if sesiones:
            trail_text += "Sesiones:\n" + "\n".join([f"{row[0]} - {row[1]} - {row[2]} - {row[3]}" for row in sesiones])
        else:
            trail_text += "No hay auditoría disponible para sesiones."

        # Mostrar mensaje con los resultados combinados
        messagebox.showinfo("Auditoría", trail_text)

    # Métodos de Información de la Base de Datos
    def view_instance_info(self):
        info = self.controlador.info_instancia()
        if info:
            info_text = "\n".join([f"{row[0]}: {row[1]}" for row in info])
            messagebox.showinfo("Información de la Instancia", info_text)
        else:
            messagebox.showinfo("Información de la Instancia", "No hay información de la instancia disponible.")

    def view_database_size(self):
        size = self.controlador.tam_bd()
        if size and size[0] is not None:  # Verificamos que size no sea None y que el primer elemento no sea None
            messagebox.showinfo("Tamaño de la Base de Datos", f"Tamaño total: {size[0]:.2f} MB")
        else:
            messagebox.showinfo("Tamaño de la Base de Datos", "No se pudo obtener el tamaño de la base de datos.")

    def view_data_files(self):
        # Obtener archivos de datos
        data_files = self.controlador.all_files()
        # Obtener archivos temporales
        temp_files = self.controlador.temp_files()
        # Obtener archivos de redo log
        redo_log_files = self.controlador.redo_log_files()
    
        # Preparar texto para mostrar
        file_text = "Archivos de Datos:\n"
        if data_files:
            file_text += "\n".join([f"{row[0]}: {row[1]}" for row in data_files]) + "\n"
        else:
            file_text += "No se encontraron archivos de datos.\n"

        file_text += "\nArchivos Temporales:\n"
        if temp_files:
            file_text += "\n".join([f"{row[0]}: {row[1]}" for row in temp_files]) + "\n"
        else:
            file_text += "No se encontraron archivos temporales.\n"

        file_text += "\nArchivos de Redo Log:\n"
        if redo_log_files:
            file_text += "\n".join([f"{row[0]}" for row in redo_log_files]) + "\n"
        else:
            file_text += "No se encontraron archivos de redo log.\n"

        # Mostrar el mensaje combinado
        messagebox.showinfo("Archivos del Sistema", file_text)

    def disconnect(self):
        # Cerrar la conexión y volver a la pantalla de inicio de sesión
        self.controlador.conector.close()
        for widget in self.root.winfo_children():
            widget.destroy()
        self.create_login_frame()

    # Añadir contenido a la pestaña de "Respaldos"
    def agregar_funcionalidad_respaldo(tab_respaldos):
        tk.Label(tab_respaldos, text="Seleccione el tipo de respaldo:").pack(pady=10)

        # Funciones de respaldo
        def crear_respaldo(tipo):
            if tipo == "schema":
                esquema = simpledialog.askstring("Esquema", "Ingrese el nombre del esquema:")
                resultado = ejecutar_expdp("schema", esquema=esquema)
            elif tipo == "tabla":
                esquema = simpledialog.askstring("Esquema", "Ingrese el nombre del esquema:")
                tabla = simpledialog.askstring("Tabla", "Ingrese el nombre de la tabla:")
                resultado = ejecutar_expdp("tabla", esquema=esquema, tabla=tabla)
            elif tipo == "full":
                resultado = ejecutar_expdp("full")

            messagebox.showinfo("Resultado del Respaldo", resultado)

        # Botones para cada tipo de respaldo
        btn_schema = tk.Button(tab_respaldos, text="Respaldo por Schema", command=lambda: crear_respaldo("schema"))
        btn_schema.pack(pady=5)

        btn_tabla = tk.Button(tab_respaldos, text="Respaldo por Tabla", command=lambda: crear_respaldo("tabla"))
        btn_tabla.pack(pady=5)

        btn_full = tk.Button(tab_respaldos, text="Respaldo Full", command=lambda: crear_respaldo("full"))
        btn_full.pack(pady=5)

    # Función para ejecutar el comando expdp
def ejecutar_expdp(tipo_respaldo, esquema=None, tabla=None):
    try:
        dumpfile = f'{tipo_respaldo}_backup.dmp'
        logfile = f'{tipo_respaldo}_backup.log'
        if tipo_respaldo == "schema" and esquema:
            command = f"expdp system/password schemas={esquema} dumpfile={dumpfile} logfile={logfile}"
        elif tipo_respaldo == "tabla" and esquema and tabla:
            command = f"expdp system/password tables={esquema}.{tabla} dumpfile={dumpfile} logfile={logfile}"
        elif tipo_respaldo == "full":
            command = f"expdp system/password full=y dumpfile={dumpfile} logfile={logfile}"
        else:
            return "Tipo de respaldo inválido"
        # Ejecutar el comando expdp
        subprocess.run(command, shell=True, check=True)
        return f"Respaldo {tipo_respaldo} realizado correctamente en {dumpfile}"
    except subprocess.CalledProcessError as e:
        return f"Error al realizar respaldo: {e}"

if __name__ == "__main__":
    root = tk.Tk()
    app = OracleDBManager(root)
    root.mainloop()
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog


