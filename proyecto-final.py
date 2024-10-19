import cx_Oracle
import tkinter as tk
from tkinter import ttk  # Asegura importar ttk desde tkinter
from tkinter import messagebox
from tkinter import simpledialog

class Controlador:
    def __init__(self):
        self.DRIVER = "oracle.jdbc.driver.OracleDriver"  # No se usa en cx_Oracle
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
        query = "SELECT * FROM V$DATAFILE"
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            return cursor
        except cx_Oracle.Error as e:
            print(f"Error al obtener todos los archivos: {e}")
            return None

    def temp_files(self):
        query = "SELECT * FROM V$TEMPFILE"
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
        query = "SELECT SUM(BYTES)/1024/1024 MB FROM DBA_EXTENTS"
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            return cursor
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
        SELECT SUBSTR(LPAD(' ', LEVEL-1) || OPERATION || ' (' || OPTIONS|| ')', 1, 30) OPERACION,
               OBJECT_NAME OBJETO, TIMESTAMP FECHA
        FROM PLAN_TABLE
        START WITH ID = 0
        CONNECT BY PRIOR ID=PARENT_ID
        """
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            return cursor
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

class OracleDBManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Oracle Database Manager")
        self.root.geometry("800x600")
        
        self.controlador = Controlador()
        
        self.create_login_frame()

    def create_login_frame(self):
        self.login_frame = ttk.Frame(self.root, padding="20")
        self.login_frame.pack(expand=True, fill="both")

        ttk.Label(self.login_frame, text="Username:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.username_entry = ttk.Entry(self.login_frame)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(self.login_frame, text="Password:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.password_entry = ttk.Entry(self.login_frame, show="*")
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)

        ttk.Button(self.login_frame, text="Connect", command=self.connect).grid(row=2, column=0, columnspan=2, pady=10)

        self.status_label = ttk.Label(self.login_frame, text="Status: Disconnected", foreground="red")
        self.status_label.grid(row=3, column=0, columnspan=2)

    def connect(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if self.controlador.get_conexion(username, password):
            self.status_label.config(text="Status: Connected", foreground="green")
            self.login_frame.destroy()
            self.create_main_interface()
        else:
            messagebox.showerror("Connection Error", "Failed to connect to the database.")

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

        ttk.Button(self.root, text="Disconnect", command=self.disconnect).pack(pady=10)

    def create_user_management_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="User Management")

        ttk.Button(tab, text="Create User", command=self.create_user).pack(pady=5)
        ttk.Button(tab, text="Create Role", command=self.create_role).pack(pady=5)
        ttk.Button(tab, text="Grant Role to User", command=self.grant_role_to_user).pack(pady=5)
        ttk.Button(tab, text="Revoke Role from User", command=self.revoke_role_from_user).pack(pady=5)
        ttk.Button(tab, text="View User Roles", command=self.view_user_roles).pack(pady=5)

    def create_session_management_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Session Management")

        ttk.Button(tab, text="View Active Sessions", command=self.view_active_sessions).pack(pady=5)
        ttk.Button(tab, text="Kill Session", command=self.kill_session).pack(pady=5)

    def create_tablespace_management_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Tablespace Management")

        ttk.Button(tab, text="View Tablespaces", command=self.view_tablespaces).pack(pady=5)
        ttk.Button(tab, text="Create Tablespace", command=self.create_tablespace).pack(pady=5)
        ttk.Button(tab, text="Drop Tablespace", command=self.drop_tablespace).pack(pady=5)

    def create_backup_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Backup & Recovery")

        ttk.Button(tab, text="Backup Schema", command=lambda: self.backup("schema")).pack(pady=5)
        ttk.Button(tab, text="Backup Table", command=lambda: self.backup("table")).pack(pady=5)
        ttk.Button(tab, text="Full Backup", command=lambda: self.backup("full")).pack(pady=5)
        ttk.Button(tab, text="Restore Backup", command=self.restore_backup).pack(pady=5)

    def create_query_optimization_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Query Optimization")

        ttk.Button(tab, text="Analyze Query", command=self.analyze_query).pack(pady=5)
        ttk.Button(tab, text="View Execution Plan", command=self.view_execution_plan).pack(pady=5)
        ttk.Button(tab, text="Generate Table Statistics", command=self.generate_table_statistics).pack(pady=5)

    def create_auditing_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Auditing")

        ttk.Button(tab, text="Enable Connection Auditing", command=self.controlador.auditar_conexiones).pack(pady=5)
        ttk.Button(tab, text="Enable Session Auditing", command=self.controlador.auditar_inicios_sesion).pack(pady=5)
        ttk.Button(tab, text="View Audit Trail", command=self.view_audit_trail).pack(pady=5)

    def create_database_info_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Database Info")

        ttk.Button(tab, text="View Instance Info", command=self.view_instance_info).pack(pady=5)
        ttk.Button(tab, text="View Database Size", command=self.view_database_size).pack(pady=5)
        ttk.Button(tab, text="View Data Files", command=self.view_data_files).pack(pady=5)

    # User Management Methods
    def create_user(self):
        username = simpledialog.askstring("Create User", "Enter new username:")
        if username and self.controlador.crear_usuario(username):
            messagebox.showinfo("Success", f"User {username} created successfully.")
        else:
            messagebox.showerror("Error", "Failed to create user.")

    def create_role(self):
        role = simpledialog.askstring("Create Role", "Enter new role name:")
        if role and self.controlador.crear_rol(role):
            messagebox.showinfo("Success", f"Role {role} created successfully.")
        else:
            messagebox.showerror("Error", "Failed to create role.")

    def grant_role_to_user(self):
        user = simpledialog.askstring("Grant Role", "Enter username:")
        role = simpledialog.askstring("Grant Role", "Enter role name:")
        if user and role and self.controlador.otorgar_rol_usuario(role, user):
            messagebox.showinfo("Success", f"Role {role} granted to user {user}.")
        else:
            messagebox.showerror("Error", "Failed to grant role.")

    def revoke_role_from_user(self):
        user = simpledialog.askstring("Revoke Role", "Enter username:")
        role = simpledialog.askstring("Revoke Role", "Enter role name:")
        if user and role and self.controlador.revocar_rol_usuario(role, user):
            messagebox.showinfo("Success", f"Role {role} revoked from user {user}.")
        else:
            messagebox.showerror("Error", "Failed to revoke role.")

    def view_user_roles(self):
        user = simpledialog.askstring("View Roles", "Enter username:")
        if user:
            roles = self.controlador.cargar_roles(user)
            if roles:
                role_list = "\n".join([row[0] for row in roles])
                messagebox.showinfo("User Roles", f"Roles for {user}:\n{role_list}")
            else:
                messagebox.showinfo("User Roles", f"No roles found for {user}")

    # Session Management Methods
    def view_active_sessions(self):
        sessions = self.controlador.cargar_sesiones_bd()
        if sessions:
            session_list = "\n".join([f"SID: {row[0]}, Serial#: {row[1]}, Username: {row[2]}, Program: {row[3]}" for row in sessions])
            messagebox.showinfo("Active Sessions", session_list)
        else:
            messagebox.showinfo("Active Sessions", "No active sessions found")

    def kill_session(self):
        sid = simpledialog.askstring("Kill Session", "Enter SID:")
        serial = simpledialog.askstring("Kill Session", "Enter Serial#:")
        if sid and serial:
            if self.controlador.cerrar_sesion_bd(sid, serial, 1):
                messagebox.showinfo("Success", f"Session {sid},{serial} killed successfully.")
            else:
                messagebox.showerror("Error", "Failed to kill session.")

    # Tablespace Management Methods
    def view_tablespaces(self):
        tablespaces = self.controlador.tam_tablespaces()
        if tablespaces:
            ts_list = "\n".join([f"{row[0]}: {row[2]}MB total, {row[3]}MB used, {row[4]}MB free" for row in tablespaces])
            messagebox.showinfo("Tablespaces", ts_list)
        else:
            messagebox.showinfo("Tablespaces", "No tablespaces found")

    def create_tablespace(self):
        # This method would require additional implementation to create tablespaces
        messagebox.showinfo("Info", "Tablespace creation not implemented in this version.")

    def drop_tablespace(self):
        # This method would require additional implementation to drop tablespaces
        messagebox.showinfo("Info", "Tablespace dropping not implemented in this version.")

    # Backup & Recovery Methods
    def backup(self, backup_type):
        # This method would require additional implementation to perform backups
        messagebox.showinfo("Info", f"{backup_type.capitalize()} backup not implemented in this version.")

    def restore_backup(self):
        # This method would require additional implementation to restore backups
        messagebox.showinfo("Info", "Backup restoration not implemented in this version.")

    # Query Optimization Methods
    def analyze_query(self):
        query = simpledialog.askstring("Analyze Query", "Enter SQL query:")
        if query:
            result = self.controlador.executar_query_optimizar(query)
            if result == "true":
                messagebox.showinfo("Success", "Query analyzed successfully.")
            else:
                messagebox.showerror("Error", f"Failed to analyze query: {result}")

    def view_execution_plan(self):
        plan = self.controlador.obtener_explain_plan()
        if plan:
            plan_text = "\n".join([f"{row[0]} - {row[1]} ({row[2]})" for row in plan])
            messagebox.showinfo("Execution Plan", plan_text)
        else:
            messagebox.showinfo("Execution Plan", "No execution plan available.")

    def generate_table_statistics(self):
        schema = simpledialog.askstring("Generate Statistics", "Enter schema name:")
        table = simpledialog.askstring("Generate Statistics", "Enter table name (or 'Schema' for all tables):")
        if schema and table:
            if self.controlador.genera_stats(schema, table):
                messagebox.showinfo("Success", "Statistics generated successfully.")
                messagebox.showinfo(self.controlador.consulta_stats(self, table))
            else:
                messagebox.showerror("Error", "Failed to generate statistics.")

    # Auditing Methods
    def view_audit_trail(self):
        audit_trail = self.controlador.ver_auditoria_por_accion()
        if audit_trail:
            trail_text = "\n".join([f"{row[0]} - {row[1]} - {row[2]} - {row[3]} on {row[4]}" for row in audit_trail])
            messagebox.showinfo("Audit Trail", trail_text)
        else:
            messagebox.showinfo("Audit Trail", "No audit trail available.")

    # Database Info Methods
    def view_instance_info(self):
        info = self.controlador.info_instancia()
        if info:
            info_text = "\n".join([f"{row[0]}: {row[1]}" for row in info])
            messagebox.showinfo("Instance Info", info_text)
        else:
            messagebox.showinfo("Instance Info", "No instance information available.")

    def view_database_size(self):
        size = self.controlador.tam_bd()
        if size:
            messagebox.showinfo("Database Size", f"Total size: {size[0][0]:.2f} MB")
        else:
            messagebox.showinfo("Database Size", "Unable to retrieve database size.")

    def view_data_files(self):
        files = self.controlador.all_files()
        if files:
            file_text = "\n".join([f"{row[0]}: {row[1]}" for row in files])
            messagebox.showinfo("Data Files", file_text)
        else:
            messagebox.showinfo("Data Files", "No data files found.")

    def disconnect(self):
        # Close the connection and return to the login screen
        self.controlador.conector.close()
        for widget in self.root.winfo_children():
            widget.destroy()
        self.create_login_frame()

if __name__ == "__main__":
    root = tk.Tk()
    app = OracleDBManager(root)
    root.mainloop()