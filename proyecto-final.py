import cx_Oracle
import tkinter as tk
from tkinter import ttk  # Asegura importar ttk desde tkinter
from tkinter import messagebox
from tkinter import simpledialog, scrolledtext
import subprocess
import threading
import logging


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
            print("Estadística realizada con éxito!")
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

    def crear_usuario(self, usuario, contrasena):
        try:
            cursor = self.conector.cursor()
            cursor.execute("ALTER SESSION SET \"_ORACLE_SCRIPT\"=TRUE")

            # Crear el usuario con la contraseña
            cursor.execute(f"CREATE USER {usuario} IDENTIFIED BY {contrasena}")
            self.conector.commit()
            print(f"Usuario '{usuario}' creado exitosamente.")
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

    def redimensionar_tablespace(self, nombre_tablespace, nuevo_tamano):
        ruta_datafile = f"C:\Archivos Oracle\{nombre_tablespace}.dbf"

        query = f"ALTER DATABASE DATAFILE '{ruta_datafile}' RESIZE {nuevo_tamano}"
        try:
            cursor = self.conector.cursor()
            cursor.execute(query)
            self.conector.commit()
            print(f"El tamaño del tablespace '{nombre_tablespace}' ha sido cambiado a {nuevo_tamano}.")
            return True
        except cx_Oracle.Error as e:
            print(f"Error al cambiar el tamaño del tablespace: {e}")
            return False
        
    def crear_tablespace(self, nombre_tablespace: str, tamano: str, tipo: str = "normal") -> bool:
        cursor = None
        try:
            # Validaciones de entrada
            if not isinstance(nombre_tablespace, str) or not nombre_tablespace.strip():
                logging.error("El nombre del tablespace no puede estar vacío")
                return False

            if not isinstance(tamano, str) or not tamano.strip():
                logging.error("El tamaño no puede estar vacío")
                return False

            # Validar formato del tamaño con expresión regular
            import re
            if not re.match(r'^\d+[MG]$', tamano):
                logging.error("El tamaño debe estar en formato válido (ejemplo: 100M o 1G)")
                return False

            # Validar tipo de tablespace
            tipo = tipo.lower()
            if tipo not in ["normal", "temporal"]:
                logging.error("El tipo de tablespace debe ser 'normal' o 'temporal'")
                return False

            # Construir ruta del archivo
            import os
            directorio_base = "C:\\ORACLE_FILES"
            if not os.path.exists(directorio_base):
                os.makedirs(directorio_base)
            
            ruta_archivo = os.path.join(directorio_base, f"{nombre_tablespace}.dbf")

            cursor = self.conector.cursor()
            
            # Habilitar Oracle Script
            cursor.execute('ALTER SESSION SET "_ORACLE_SCRIPT" = TRUE')

            # Construir y ejecutar la consulta SQL
            sql = (
                f"""CREATE {'TEMPORARY ' if tipo == 'temporal' else ''}TABLESPACE "{nombre_tablespace}" 
                {'TEMPFILE' if tipo == 'temporal' else 'DATAFILE'} '{ruta_archivo}' 
                SIZE {tamano} 
                {' AUTOEXTEND ON' if tipo == 'temporal' else ' ONLINE'}"""
            )

            logging.info(f"Ejecutando SQL: {sql}")
            cursor.execute(sql)
            self.conector.commit()
            
            logging.info(f"Tablespace '{nombre_tablespace}' creado exitosamente")
            return True

        except cx_Oracle.DatabaseError as e:
            error_obj, = e.args
            error_mensaje = f"Error al crear el tablespace: {error_obj.message}"
            logging.error(error_mensaje)
            messagebox.showerror("Error", error_mensaje)
            return False

        except Exception as e:
            error_mensaje = f"Error inesperado al crear el tablespace: {str(e)}"
            logging.error(error_mensaje)
            messagebox.showerror("Error", error_mensaje)
            return False

        finally:
            if cursor:
                cursor.close()

class OracleDBManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Administrador de Base de Datos Oracle")
        self.root.geometry("880x600")
        
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

        ttk.Button(self.login_frame, text="Conectar", command=self.connect, width=15, style="TButton").grid(row=3, column=0, columnspan=2, pady=15, padx=(18,0))

        self.status_label = ttk.Label(self.login_frame, text="Estado: Desconectado", foreground="red", font=("Tahoma", 10))
        self.status_label.grid(row=4, column=0, columnspan=2, padx=(15,0))

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

        button_frame = ttk.Frame(tab)
        button_frame.place(relx=0.5, rely=0.4, anchor="center")

        ttk.Button(button_frame, text="Crear Usuario", command=self.create_user).pack(pady=5)
        ttk.Button(button_frame, text="Crear Rol", command=self.create_role).pack(pady=5)
        ttk.Button(button_frame, text="Otorgar Rol a Usuario", command=self.grant_role_to_user).pack(pady=5)
        ttk.Button(button_frame, text="Revocar Rol de Usuario", command=self.revoke_role_from_user).pack(pady=5)
        ttk.Button(button_frame, text="Ver Roles de Usuario", command=self.view_user_roles).pack(pady=5)

    def create_session_management_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Gestión de Sesiones")

        button_frame = ttk.Frame(tab)
        button_frame.place(relx=0.5, rely=0.4, anchor="center")

        ttk.Button(button_frame, text="Ver Sesiones Activas", command=self.view_active_sessions).pack(pady=5)
        ttk.Button(button_frame, text="Terminar Sesión", command=self.kill_session).pack(pady=5)

    def create_tablespace_management_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Gestión de Tablespaces")

        button_frame = ttk.Frame(tab)
        button_frame.place(relx=0.5, rely=0.4, anchor="center")

        ttk.Button(button_frame, text="Ver Tablespaces", command=self.view_tablespaces).pack(pady=5)
        ttk.Button(button_frame, text="Crear Tablespace", command=self.crear_tablespace).pack(pady=5)
        ttk.Button(button_frame, text="Eliminar Tablespace", command=self.drop_tablespace).pack(pady=5)
        ttk.Button(button_frame, text="Cambiar Tamaño Tablespace", command=self.resize_tablespace).pack(pady=5)
        ttk.Button(button_frame, text="Crear Indice", command=self.create_index).pack(pady=5)
        ttk.Button(button_frame, text="Eliminar Indice", command=self.drop_index).pack(pady=5)
    
    def create_backup_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Respaldo y Recuperación")

        button_frame = ttk.Frame(tab)
        button_frame.place(relx=0.5, rely=0.4, anchor="center")

        ttk.Button(button_frame, text="Respaldo de Esquema", command=lambda: self.backup("schema")).pack(pady=5)
        ttk.Button(button_frame, text="Respaldo de Tabla", command=lambda: self.backup("table")).pack(pady=5)
        ttk.Button(button_frame, text="Respaldo Completo", command=lambda: self.backup("full")).pack(pady=5)
        ttk.Button(button_frame, text="Restaurar Respaldo", command=self.restore_backup).pack(pady=5)
        
    def create_query_optimization_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Optimización de Consultas")

        button_frame = ttk.Frame(tab)
        button_frame.place(relx=0.5, rely=0.4, anchor="center")

        ttk.Button(button_frame, text="Analizar Consulta", command=self.analyze_query).pack(pady=5)
        ttk.Button(button_frame, text="Ver Plan de Ejecución", command=self.view_execution_plan).pack(pady=5)
        ttk.Button(button_frame, text="Generar Estadísticas de Tabla", command=self.generate_table_statistics).pack(pady=5)

    def create_auditing_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Auditoría")

        button_frame = ttk.Frame(tab)
        button_frame.place(relx=0.5, rely=0.4, anchor="center")

        ttk.Button(button_frame, text="Habilitar Auditoría de Conexiones", command=self.habilitar_auditoria_conexiones).pack(pady=5)
        ttk.Button(button_frame, text="Habilitar Auditoría de Sesiones", command=self.habilitar_auditoria_sesiones).pack(pady=5)
        ttk.Button(button_frame, text="Ver Registro de Auditoría", command=self.view_audit_trail).pack(pady=5)

    def create_database_info_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Información de la Base de Datos")

        button_frame = ttk.Frame(tab)
        button_frame.place(relx=0.5, rely=0.4, anchor="center")

        ttk.Button(button_frame, text="Ver Información de la Instancia", command=self.view_instance_info).pack(pady=5)
        ttk.Button(button_frame, text="Ver Tamaño de la Base de Datos", command=self.view_database_size).pack(pady=5)
        ttk.Button(button_frame, text="Ver Archivos de Datos", command=self.view_data_files).pack(pady=5)

    # User Management Methods
    def create_user(self):
        # Crear ventana Toplevel
        dialog = tk.Toplevel(self.root)
        dialog.title("Crear Usuario")

        tk.Label(dialog, text="Ingrese el nuevo nombre de usuario:", font=("Tahoma", 10)).grid(row=0, column=0, padx=10, pady=10)
        username_entry = tk.Entry(dialog)
        username_entry.grid(row=0, column=1, padx=10, pady=10)

        tk.Label(dialog, text="Ingrese la contraseña para el usuario:", font=("Tahoma", 10)).grid(row=1, column=0, padx=10, pady=10)
        password_entry = tk.Entry(dialog, show="*")
        password_entry.grid(row=1, column=1, padx=10, pady=10)

        def on_accept():
            username = username_entry.get()
            password = password_entry.get()
            if username and password:
                if self.controlador.crear_usuario(username, password):
                    messagebox.showinfo("Éxito", f"Usuario {username} creado exitosamente.")
                    dialog.destroy() 
                else:
                    messagebox.showerror("Error", "No se pudo crear el usuario.")
            else:
                messagebox.showwarning("Advertencia", "El campo de usuario no puede estar vacío.")

        def on_cancel():
            dialog.destroy()
        
        accept_button = tk.Button(dialog, text="Crear Usuario", command=on_accept, font=("Tahoma", 10), width=12)
        accept_button.grid(row=2, column=0, padx=(170, 0), pady=10)

        cancel_button = tk.Button(dialog, text="Cancelar", command=on_cancel, font=("Tahoma", 10), width=12)
        cancel_button.grid(row=2, column=1, padx=(5, 15), pady=10)

    def create_role(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Crear Rol")

        tk.Label(dialog, text="Ingrese el nuevo nombre del rol:", font=("Tahoma", 10)).grid(row=0, column=0, padx=10, pady=10)
        role_entry = tk.Entry(dialog)
        role_entry.grid(row=0, column=1, padx=10, pady=10)

        def on_accept():
            role = role_entry.get()
            if role:
                if self.controlador.crear_rol(role):
                    messagebox.showinfo("Éxito", f"Rol {role} creado exitosamente.")
                    dialog.destroy()
                else:
                    messagebox.showerror("Error", "No se pudo crear el rol o ya existe.")
            else:
                messagebox.showwarning("Advertencia", "El campo de rol no puede estar vacío.")

        def on_cancel():
            dialog.destroy()

        # Botones Aceptar y Cancelar
        accept_button = tk.Button(dialog, text="Crear Rol", command=on_accept, font=("Tahoma", 10), width=12)
        accept_button.grid(row=1, column=0, padx=(170, 0), pady=10)

        cancel_button = tk.Button(dialog, text="Cancelar", command=on_cancel, font=("Tahoma", 10), width=12)
        cancel_button.grid(row=1, column=1, padx=(5, 15), pady=10)

    def grant_role_to_user(self):
        # Crear ventana emergente personalizada
        dialog = tk.Toplevel(self.root)
        dialog.title("Otorgar Rol a Usuario")

        tk.Label(dialog, text="Ingrese el nombre de usuario:", font=("Tahoma", 10)).grid(row=0, column=0, padx=10, pady=10)
        user_entry = tk.Entry(dialog)
        user_entry.grid(row=0, column=1, padx=10, pady=10)

        tk.Label(dialog, text="Ingrese el nombre del rol:", font=("Tahoma", 10)).grid(row=1, column=0, padx=10, pady=10)
        role_entry = tk.Entry(dialog)
        role_entry.grid(row=1, column=1, padx=10, pady=10)

        def on_submit():
            user = user_entry.get()
            role = role_entry.get()
            if user and role and self.controlador.otorgar_rol_usuario(role, user):
                messagebox.showinfo("Éxito", f"Rol '{role}' otorgado al usuario '{user}'.")
                dialog.destroy()
            else:
                messagebox.showerror("Error", "No se pudo otorgar el rol.")

        def on_cancel():
            dialog.destroy()

        submit_button = tk.Button(dialog, text="Otorgar Rol", command=on_submit, width=12, font=("Tahoma", 10))
        submit_button.grid(row=2, column=0, columnspan=2, padx=(10, 5), pady=10)

        cancel_button = tk.Button(dialog, text="Cancelar", command=on_cancel, width=12, font=("Tahoma", 10))
        cancel_button.grid(row=2, column=1, padx=(20, 10), pady=10)

        dialog.transient(self.root) 
        dialog.grab_set()

    def revoke_role_from_user(self):
        # Crear ventana emergente personalizada
        dialog = tk.Toplevel(self.root)
        dialog.title("Revocar Rol de Usuario")

        tk.Label(dialog, text="Ingrese el nombre de usuario:", font=("Tahoma", 10)).grid(row=0, column=0, padx=10, pady=10)
        user_entry = tk.Entry(dialog)
        user_entry.grid(row=0, column=1, padx=10, pady=10)

        tk.Label(dialog, text="Ingrese el nombre del rol:", font=("Tahoma", 10)).grid(row=1, column=0, padx=10, pady=10)
        role_entry = tk.Entry(dialog)
        role_entry.grid(row=1, column=1, padx=10, pady=10)

        def on_submit():
            user = user_entry.get()
            role = role_entry.get()
            if user and role and self.controlador.revocar_rol_usuario(role, user):
                messagebox.showinfo("Éxito", f"Rol '{role}' revocado del usuario '{user}'.")
                dialog.destroy()
            else:
                messagebox.showerror("Error", "No se pudo revocar el rol.")

        def on_cancel():
            dialog.destroy()

        submit_button = tk.Button(dialog, text="Revocar Rol", command=on_submit, font=("Tahoma", 10))
        submit_button.grid(row=2, column=0, columnspan=2, padx=(10, 5), pady=10)

        cancel_button = tk.Button(dialog, text="Cancelar", command=on_cancel, width=10, font=("Tahoma", 10))
        cancel_button.grid(row=2, column=1, padx=(5, 10), pady=10)

        dialog.transient(self.root) 
        dialog.grab_set()

    def view_user_roles(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Ver Roles de Usuario")

        tk.Label(dialog, text="Ingrese el nombre de usuario:", font=("Tahoma", 10)).grid(row=0, column=0, padx=10, pady=10)
        user_entry = tk.Entry(dialog)
        user_entry.grid(row=0, column=1, padx=10, pady=10)

        def on_accept():
            user = user_entry.get()
            if user:
                roles = self.controlador.cargar_roles(user)
                if roles:
                    role_list = "\n".join([row[0] for row in roles])
                    messagebox.showinfo("Roles del Usuario", f"Roles para {user}:\n{role_list}")
                else:
                    messagebox.showinfo("Roles del Usuario", f"No se encontraron roles para {user}")
            else:
                messagebox.showwarning("Advertencia", "El campo de usuario no puede estar vacío.")

        def on_cancel():
            dialog.destroy()

        # Botones Aceptar y Cancelar
        accept_button = tk.Button(dialog, text="Aceptar", command=on_accept, font=("Tahoma", 10), width=12)
        accept_button.grid(row=1, column=0, padx=(170, 0), pady=10)

        cancel_button = tk.Button(dialog, text="Cancelar", command=on_cancel, font=("Tahoma", 10), width=12)
        cancel_button.grid(row=1, column=1, padx=(5, 15), pady=10)
        

    # Session Management Methods
    def view_active_sessions(self):
        sessions = self.controlador.cargar_sesiones_bd()
        
        # Crear una nueva ventana para mostrar las sesiones activas
        if sessions:
            # Crear una ventana nueva
            sessions_window = tk.Toplevel(self.root)
            sessions_window.title("Sesiones Activas")
            sessions_window.geometry("500x300")

            # Crear el Treeview para mostrar las sesiones
            tree = ttk.Treeview(sessions_window, columns=("SID", "Serial#", "Usuario", "Programa"), show="headings")
            tree.heading("SID", text="SID")
            tree.heading("Serial#", text="Serial#")
            tree.heading("Usuario", text="Usuario")
            tree.heading("Programa", text="Programa")
            tree.column("SID", anchor="center", width=100)
            tree.column("Serial#", anchor="center", width=100)
            tree.column("Usuario", anchor="center",width=150)
            tree.column("Programa", anchor="center",width=150)

            # Insertar las sesiones en el Treeview
            for row in sessions:
                tree.insert("", tk.END, values=row)

            tree.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

            # Botón para cerrar la ventana
            close_button = tk.Button(sessions_window, text="Cerrar", command=sessions_window.destroy, width=12)
            close_button.pack(pady=10)

        else:
            messagebox.showinfo("Sesiones Activas", "No se encontraron sesiones activas")
        

    def kill_session(self):
        # Crear ventana emergente personalizada
        dialog = tk.Toplevel(self.root)
        dialog.title("Terminar Sesión")

        tk.Label(dialog, text="Ingrese SID:", font=("Tahoma", 10)).grid(row=0, column=0, padx=10, pady=10)
        sid_entry = tk.Entry(dialog)
        sid_entry.grid(row=0, column=1, padx=10, pady=10)

        tk.Label(dialog, text="Ingrese Serial#:", font=("Tahoma", 10)).grid(row=1, column=0, padx=10, pady=10)
        serial_entry = tk.Entry(dialog)
        serial_entry.grid(row=1, column=1, padx=10, pady=10)

        def on_submit():
            sid = sid_entry.get()
            serial = serial_entry.get()
            if sid and serial:
                if self.controlador.cerrar_sesion_bd(sid, serial, 1):
                    messagebox.showinfo("Éxito", f"Sesión {sid}, {serial} terminada exitosamente.")
                    dialog.destroy()
                else:
                    messagebox.showerror("Error", "No se pudo terminar la sesión.")
            else:
                messagebox.showwarning("Advertencia", "Por favor complete ambos campos.")

        def on_cancel():
            dialog.destroy()

        submit_button = tk.Button(dialog, text="Terminar Sesión", command=on_submit, font=("Tahoma", 10))
        submit_button.grid(row=2, column=0, columnspan=2, padx=(10, 5), pady=10)

        cancel_button = tk.Button(dialog, text="Cancelar", command=on_cancel, width=10, font=("Tahoma", 10))
        cancel_button.grid(row=2, column=1, padx=(80, 5), pady=10)

        dialog.transient(self.root) 
        dialog.grab_set()

    # Tablespace Management Methods
    def view_tablespaces(self):
        tablespaces = self.controlador.tam_tablespaces()
        
        if tablespaces:
            # Crear una nueva ventana emergente para mostrar la tabla
            dialog = tk.Toplevel(self.root)
            dialog.title("Tablespaces")

            dialog.geometry("500x300")

            tree = ttk.Treeview(dialog, columns=("Nombre", "Tamaño Total", "Usado", "Libre"), show="headings")
            tree.heading("Nombre", text="Nombre")
            tree.heading("Tamaño Total", text="Tamaño Total (MB)")
            tree.heading("Usado", text="Usado (MB)")
            tree.heading("Libre", text="Libre (MB)")

            tree.column("Nombre", anchor="center", width=150)
            tree.column("Tamaño Total", anchor="center", width=100)
            tree.column("Usado", anchor="center", width=100)
            tree.column("Libre", anchor="center", width=100)

            for row in tablespaces:
                tree.insert("", "end", values=(row[0], row[2], row[3], row[4]))

            tree.pack(expand=True, fill="both")

            tk.Button(dialog, text="Cerrar", command=dialog.destroy, width=12).pack(pady=10)
        else:
            messagebox.showinfo("Tablespaces", "No se encontraron tablespaces")

    def crear_tablespace(self):
        # Crear el diálogo de entrada
        dialog = tk.Toplevel(self.root)
        dialog.title("Crear Tablespace")

        # Entradas para nombre del tablespace y tamaño
        tk.Label(dialog, text="Ingrese el nombre del tablespace:", font=("Tahoma", 10)).grid(row=0, column=0, padx=10, pady=10)
        nombre_tablespace_entry = tk.Entry(dialog)
        nombre_tablespace_entry.grid(row=0, column=1, padx=10, pady=10)

        tk.Label(dialog, text="Ingrese el tamaño (ejemplo: 100M):", font=("Tahoma", 10)).grid(row=1, column=0, padx=10, pady=10)
        nuevo_tamano_entry = tk.Entry(dialog)
        nuevo_tamano_entry.grid(row=1, column=1, padx=10, pady=10)

        # Selección del tipo de tablespace
        tk.Label(dialog, text="Tipo de Tablespace:", font=("Tahoma", 10)).grid(row=2, column=0, padx=10, pady=10)
        tipo_tablespace_var = tk.StringVar(value="normal")
        tipo_tablespace_normal = tk.Radiobutton(dialog, text="Normal", variable=tipo_tablespace_var, value="normal")
        tipo_tablespace_normal.grid(row=2, column=1, padx=10, pady=5, sticky="w")
        tipo_tablespace_temporal = tk.Radiobutton(dialog, text="Temporal", variable=tipo_tablespace_var, value="temporal")
        tipo_tablespace_temporal.grid(row=3, column=1, padx=10, pady=5, sticky="w")

        def on_submit():
            nombre_tablespace = nombre_tablespace_entry.get()
            nuevo_tamano = nuevo_tamano_entry.get()
            tipo_tablespace = tipo_tablespace_var.get()

            if nombre_tablespace and nuevo_tamano:
                try:
                    if self.controlador.crear_tablespace(nombre_tablespace, nuevo_tamano, tipo_tablespace):
                        messagebox.showinfo("Éxito", f"Tablespace '{nombre_tablespace}' creado correctamente.")
                        dialog.destroy()
                    else:
                        messagebox.showerror("Error", "No se pudo crear el tablespace.")
                except Exception as e:
                    messagebox.showerror("Error", f"Ocurrió un error: {str(e)}")
            else:
                messagebox.showwarning("Advertencia", "Por favor complete ambos campos.")

        def on_cancel():
            dialog.destroy()

        submit_button = tk.Button(dialog, text="Crear Tablespace", command=on_submit, font=("Tahoma", 10))
        submit_button.grid(row=4, column=0, columnspan=2, padx=(10, 5), pady=10)

        cancel_button = tk.Button(dialog, text="Cancelar", command=on_cancel, width=12, font=("Tahoma", 10))
        cancel_button.grid(row=4, column=1, padx=(5, 10), pady=10)

        dialog.transient(self.root) 
        dialog.grab_set()


    def drop_tablespace(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Eliminar Tablespace")

        tk.Label(dialog, text="Ingrese el nombre del tablespace a eliminar:", font=("Tahoma", 10)).grid(row=0, column=0, padx=10, pady=10)
        tablespace_entry = tk.Entry(dialog)
        tablespace_entry.grid(row=0, column=1, padx=10, pady=10)

        def on_accept():
            nombre_tablespace = tablespace_entry.get()
            if nombre_tablespace:
                if self.controlador.borrar_tablespace(nombre_tablespace):
                    messagebox.showinfo("Éxito", f"Tablespace '{nombre_tablespace}' eliminado correctamente.")
                    dialog.destroy()
                else:
                    messagebox.showerror("Error", "No se pudo eliminar el tablespace.")
            else:
                messagebox.showwarning("Advertencia", "El campo de nombre de tablespace no puede estar vacío.")

        def on_cancel():
            dialog.destroy()

        accept_button = tk.Button(dialog, text="Aceptar", command=on_accept, font=("Tahoma", 10), width=12)
        accept_button.grid(row=1, column=0, padx=(170, 0), pady=10)

        cancel_button = tk.Button(dialog, text="Cancelar", command=on_cancel, font=("Tahoma", 10), width=12)
        cancel_button.grid(row=1, column=1, padx=(5, 15), pady=10)

    def resize_tablespace(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Cambiar Tamaño de Tablespace")

        tk.Label(dialog, text="Ingrese el nombre del tablespace:", font=("Tahoma", 10)).grid(row=0, column=0, padx=10, pady=10)
        nombre_tablespace_entry = tk.Entry(dialog)
        nombre_tablespace_entry.grid(row=0, column=1, padx=10, pady=10)

        tk.Label(dialog, text="Ingrese el nuevo tamaño (ejemplo: 100M):", font=("Tahoma", 10)).grid(row=1, column=0, padx=10, pady=10)
        nuevo_tamano_entry = tk.Entry(dialog)
        nuevo_tamano_entry.grid(row=1, column=1, padx=10, pady=10)

        def on_submit():
            nombre_tablespace = nombre_tablespace_entry.get()
            nuevo_tamano = nuevo_tamano_entry.get()

            if nombre_tablespace and nuevo_tamano:
                try:
                    if self.controlador.redimensionar_tablespace(nombre_tablespace, nuevo_tamano):
                        messagebox.showinfo("Éxito", f"Tamaño del tablespace '{nombre_tablespace}' cambiado correctamente.")
                        dialog.destroy() 
                    else:
                        messagebox.showerror("Error", "No se pudo cambiar el tamaño del tablespace.")
                except Exception as e:
                    messagebox.showerror("Error", f"Ocurrió un error: {str(e)}")
            else:
                messagebox.showwarning("Advertencia", "Por favor complete ambos campos.")
        
        def on_cancel():
            dialog.destroy()

        submit_button = tk.Button(dialog, text="Cambiar Tamaño", command=on_submit, font=("Tahoma", 10))
        submit_button.grid(row=2, column=0, columnspan=2, padx=(30,5), pady=10)

        cancel_button = tk.Button(dialog, text="Cancelar", command=on_cancel, width=12, font=("Tahoma", 10))
        cancel_button.grid(row=2, column=1, padx=(5,10), pady=10)

        # Para evitar que el usuario cierre el diálogo sin completar la acción
        dialog.transient(self.root) 
        dialog.grab_set() 

    def create_index(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Crear Índice")

        tk.Label(dialog, text="Ingrese el nombre del esquema:", font=("Tahoma", 10)).grid(row=0, column=0, padx=10, pady=5)
        schema_entry = tk.Entry(dialog)
        schema_entry.grid(row=0, column=1, padx=10, pady=5)

        tk.Label(dialog, text="Ingrese el nombre de la tabla:", font=("Tahoma", 10)).grid(row=1, column=0, padx=10, pady=5)
        table_entry = tk.Entry(dialog)
        table_entry.grid(row=1, column=1, padx=10, pady=5)

        tk.Label(dialog, text="Ingrese el nombre de la columna:", font=("Tahoma", 10)).grid(row=2, column=0, padx=10, pady=5)
        column_entry = tk.Entry(dialog)
        column_entry.grid(row=2, column=1, padx=10, pady=5)

        tk.Label(dialog, text="Ingrese el nombre del indice:", font=("Tahoma", 10)).grid(row=3, column=0, padx=10, pady=5)
        index_name_entry = tk.Entry(dialog)
        index_name_entry.grid(row=3, column=1, padx=10, pady=5)

        def on_accept():
            schema = schema_entry.get()
            table = table_entry.get()
            column = column_entry.get()
            index_name = index_name_entry.get()

            if schema and table and column and index_name:
                if self.controlador.crear_indice(schema, table, column, index_name):
                    messagebox.showinfo("Éxito", f"Índice '{index_name}' creado exitosamente en {schema}.{table}({column}).")
                    dialog.destroy()
                else:
                    messagebox.showerror("Error", "No se pudo crear el índice.")
            else:
                messagebox.showwarning("Advertencia", "Todos los campos son obligatorios.")

        def on_cancel():
            dialog.destroy()

        accept_button = tk.Button(dialog, text="Crear", command=on_accept, font=("Tahoma", 10), width=12)
        accept_button.grid(row=4, column=0, padx=(130, 0), pady=10)

        cancel_button = tk.Button(dialog, text="Cancelar", command=on_cancel, font=("Tahoma", 10), width=12)
        cancel_button.grid(row=4, column=1, padx=(0, 10), pady=10)

    def drop_index(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Eliminar Índice")

        tk.Label(dialog, text="Nombre del indice a eliminar:", font=("Tahoma", 10)).grid(row=0, column=0, padx=10, pady=10)
        index_name_entry = tk.Entry(dialog)
        index_name_entry.grid(row=0, column=1, padx=10, pady=10)

        def on_accept():
            index_name = index_name_entry.get()
            if index_name:
                if self.controlador.eliminar_indice(index_name):
                    messagebox.showinfo("Éxito", f"Índice '{index_name}' eliminado exitosamente.")
                    dialog.destroy()
                else:
                    messagebox.showerror("Error", "No se pudo eliminar el índice.")
            else:
                messagebox.showwarning("Advertencia", "El campo de nombre del índice no puede estar vacío.")

        def on_cancel():
            dialog.destroy()

        accept_button = tk.Button(dialog, text="Eliminar", command=on_accept, font=("Tahoma", 10), width=12)
        accept_button.grid(row=1, column=0, padx=(130, 5), pady=10)

        cancel_button = tk.Button(dialog, text="Cancelar", command=on_cancel, font=("Tahoma", 10), width=12)
        cancel_button.grid(row=1, column=1, padx=(0, 10), pady=10)

    #Respaldos y Recuperacion Metodos
    def backup(self, backup_type):
        dialog = tk.Toplevel(self.root)
        dialog.title("Respaldo de Base de Datos")

        tk.Label(dialog, text="Esquema:", font=("Tahoma", 10)).grid(row=0, column=0, padx=10, pady=5)
        schema_entry = tk.Entry(dialog)
        schema_entry.grid(row=0, column=1, padx=10, pady=5)

        table_label = tk.Label(dialog, text="Tabla:", font=("Tahoma", 10))
        table_entry = tk.Entry(dialog)

        if backup_type == "schema":
            table_label.grid_remove()  # Ocultar la etiqueta de tabla
            table_entry.grid_remove()   # Ocultar el campo de entrada de tabla
        elif backup_type == "table":
            table_label.grid(row=1, column=0, padx=10, pady=5)  # Mostrar la etiqueta de tabla
            table_entry.grid(row=1, column=1, padx=10, pady=5)   # Mostrar el campo de entrada de tabla
        elif backup_type == "full":
            table_label.grid_remove()  # Ocultar la etiqueta de tabla
            table_entry.grid_remove()   # Ocultar el campo de entrada de tabla

        def on_accept():
            schema = schema_entry.get()
            table = table_entry.get()
            dumpfile, logfile = "", ""
            
            if backup_type == "schema":
                if not schema:
                    messagebox.showerror("Error", "El nombre del esquema es requerido.")
                    return
                dumpfile = f'{schema}_respaldo.dmp'
                logfile = f'{schema}_respaldo.log'
                result = f"expdp 'sys/root@XE as sysdba' schemas={schema} directory=RESPALDOS dumpfile={dumpfile} logfile={logfile}"

            elif backup_type == "table":
                if not schema or not table:
                    messagebox.showerror("Error", "Los nombres del esquema y la tabla son requeridos.")
                    return
                dumpfile = f'{schema}.{table}_respaldo.dmp'
                logfile = f'{schema}.{table}_respaldo.log'
                result = f"expdp 'sys/root@XE as sysdba' tables={schema}.{table} directory=RESPALDOS dumpfile={dumpfile} logfile={logfile}"

            elif backup_type == "full":
                dumpfile = 'full_respaldo.dmp'
                logfile = 'full_respaldo.log'
                result = f"expdp 'sys/root@XE as sysdba' full=y directory=RESPALDOS dumpfile={dumpfile} logfile={logfile}"

            dialog.destroy()
            self.show_output_window(result, dumpfile, logfile, backup_type)

        def on_cancel():
            dialog.destroy()

        accept_button = tk.Button(dialog, text="Aceptar", command=on_accept, font=("Tahoma", 10), width=12)
        accept_button.grid(row=2, column=0, padx=(50, 0), pady=10)

        cancel_button = tk.Button(dialog, text="Cancelar", command=on_cancel, font=("Tahoma", 10), width=12)
        cancel_button.grid(row=2, column=1, padx=(0, 5), pady=10)

    def show_output_window(self, result, dumpfile, logfile, backup_type):
        # Crear una ventana nueva para mostrar la salida del comando de respaldo
        output_window = tk.Toplevel(self.root)
        output_window.title("Salida del Respaldo")
        output_text = scrolledtext.ScrolledText(output_window, width=80, height=20)
        output_text.pack(padx=10, pady=10)

        # Función para ejecutar el comando y actualizar la salida
        def run_backup():
            process = subprocess.Popen(result, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for line in iter(process.stdout.readline, ''):
                output_text.insert(tk.END, line)
                output_text.see(tk.END)
            process.stdout.close()
            
            # Mostrar mensajes de error si los hay
            error_output = process.stderr.read()
            if error_output:
                output_text.insert(tk.END, f"\nError:\n{error_output}")
            process.stderr.close()
            process.wait()

            # Confirmar el resultado final del proceso
            if process.returncode == 0:
                messagebox.showinfo("Respaldo completo", f"Respaldo {backup_type} realizado correctamente en {dumpfile}")
            else:
                messagebox.showerror("Error", f"Error al realizar el respaldo:\n{error_output}")

        # Ejecutar el respaldo en un hilo separado
        threading.Thread(target=run_backup).start()

    def restore_backup(self):
        # Crear un diálogo para seleccionar el tipo de restauración
        restore_type = simpledialog.askstring(
            "Restauración de respaldo", 
            "Ingrese el tipo de restauración: 'TABLAS', 'ESQUEMA', o 'COMPLETO'"
        )
        if restore_type is None:
            return  # Salir si el usuario cancela

        restore_type = restore_type.strip().upper()

        if restore_type == 'TABLAS':
            self.restore_tables()
        elif restore_type == 'ESQUEMA':
            self.restore_schema()
        elif restore_type == 'COMPLETO':
            self.restore_full()
        else:
            messagebox.showerror("Error", "Tipo de restauración no válido.")

    def restore_tables(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Restaurar Tablas")

        # Campo de entrada para el nombre de la tabla
        tk.Label(dialog, text="Tabla (esquema.tabla):", font=("Tahoma", 10)).grid(row=0, column=0, padx=10, pady=5)
        table_entry = tk.Entry(dialog)
        table_entry.grid(row=0, column=1, padx=10, pady=5)

        # Campo de entrada para el archivo de respaldo
        tk.Label(dialog, text="Archivo de respaldo (DMP):", font=("Tahoma", 10)).grid(row=1, column=0, padx=10, pady=5)
        dumpfile_entry = tk.Entry(dialog)
        dumpfile_entry.grid(row=1, column=1, padx=10, pady=5)

        # Campo de entrada para el archivo de log
        tk.Label(dialog, text="Archivo de log:", font=("Tahoma", 10)).grid(row=2, column=0, padx=10, pady=5)
        logfile_entry = tk.Entry(dialog)
        logfile_entry.grid(row=2, column=1, padx=10, pady=5)

        # Función que se ejecuta al presionar "Restaurar"
        def on_restore():
            table_name = table_entry.get()
            dumpfile = dumpfile_entry.get()
            logfile = logfile_entry.get()
            directory = "RESPALDO"  # Directorio por defecto
            
            # Validar que los campos requeridos estén completos
            if not all([table_name, dumpfile]):
                messagebox.showerror("Error", "Todos los campos son requeridos.")
                return

            # Construir el comando IMPDP
            command = f"IMPDP 'sys/root@XE as sysdba' TABLES={table_name} DIRECTORY={directory} DUMPFILE={dumpfile} LOGFILE={logfile}"
            
            # Cerrar el diálogo y ejecutar el comando
            dialog.destroy()
            self.execute_restore_command(command)

        # Botones para Restaurar y Cancelar
        restore_button = tk.Button(dialog, text="Restaurar", command=on_restore, font=("Tahoma", 10), width=12)
        restore_button.grid(row=3, column=0, padx=(5, 5), pady=10)

        cancel_button = tk.Button(dialog, text="Cancelar", command=dialog.destroy, font=("Tahoma", 10), width=12)
        cancel_button.grid(row=3, column=1, padx=(5, 10), pady=10)

    def restore_schema(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Restaurar Esquema")

        # Campo de entrada para el nombre del esquema
        tk.Label(dialog, text="Esquema:", font=("Tahoma", 10)).grid(row=0, column=0, padx=10, pady=5)
        schema_entry = tk.Entry(dialog)
        schema_entry.grid(row=0, column=1, padx=10, pady=5)

        # Campo de entrada para el archivo de respaldo
        tk.Label(dialog, text="Archivo de respaldo (DMP):", font=("Tahoma", 10)).grid(row=1, column=0, padx=10, pady=5)
        dumpfile_entry = tk.Entry(dialog)
        dumpfile_entry.grid(row=1, column=1, padx=10, pady=5)

        # Campo de entrada para el archivo de log
        tk.Label(dialog, text="Archivo de log:", font=("Tahoma", 10)).grid(row=2, column=0, padx=10, pady=5)
        logfile_entry = tk.Entry(dialog)
        logfile_entry.grid(row=2, column=1, padx=10, pady=5)

        # Función que se ejecuta al presionar "Restaurar"
        def on_restore():
            schema_name = schema_entry.get()
            dumpfile = dumpfile_entry.get()
            logfile = logfile_entry.get()
            directory = "RESPALDO"  # Directorio por defecto
            
            # Validar que los campos requeridos estén completos
            if not all([schema_name, dumpfile, logfile]):
                messagebox.showerror("Error", "Todos los campos son requeridos.")
                return

            # Construir el comando IMPDP
            command = (
                f"IMPDP 'sys/root@XE as sysdba' SCHEMAS={schema_name} "
                f"DIRECTORY={directory} DUMPFILE={dumpfile} LOGFILE={logfile}"
            )
            
            # Cerrar el diálogo y ejecutar el comando
            dialog.destroy()
            self.execute_restore_command(command)

        # Botones para Restaurar y Cancelar
        restore_button = tk.Button(dialog, text="Restaurar", command=on_restore, font=("Tahoma", 10), width=12)
        restore_button.grid(row=3, column=0, padx=(5, 5), pady=10)

        cancel_button = tk.Button(dialog, text="Cancelar", command=dialog.destroy, font=("Tahoma", 10), width=12)
        cancel_button.grid(row=3, column=1, padx=(5, 10), pady=10)

    def restore_full(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Restaurar Respaldo Completo")

        # Campo de entrada para el archivo de respaldo
        tk.Label(dialog, text="Archivo de respaldo (DMP):", font=("Tahoma", 10)).grid(row=0, column=0, padx=10, pady=5)
        dumpfile_entry = tk.Entry(dialog)
        dumpfile_entry.grid(row=0, column=1, padx=10, pady=5)

        # Campo de entrada para el archivo de log
        tk.Label(dialog, text="Archivo de log:", font=("Tahoma", 10)).grid(row=1, column=0, padx=10, pady=5)
        logfile_entry = tk.Entry(dialog)
        logfile_entry.grid(row=1, column=1, padx=10, pady=5)

        # Función que se ejecuta al presionar "Restaurar"
        def on_restore():
            dumpfile = dumpfile_entry.get()
            logfile = logfile_entry.get()
            directory = "RESPALDO"  # Directorio por defecto
            
            # Validar que los campos requeridos estén completos
            if not all([dumpfile, logfile]):
                messagebox.showerror("Error", "Todos los campos son requeridos.")
                return

            # Construir el comando IMPDP
            command = (
                f"IMPDP 'sys/root@XE as sysdba' FULL=Y "
                f"DIRECTORY={directory} DUMPFILE={dumpfile} LOGFILE={logfile}"
            )
            
            # Cerrar el diálogo y ejecutar el comando
            dialog.destroy()
            self.execute_restore_command(command)

        # Botones para Restaurar y Cancelar
        restore_button = tk.Button(dialog, text="Restaurar", command=on_restore, font=("Tahoma", 10), width=12)
        restore_button.grid(row=2, column=0, padx=(5, 5), pady=10)
        cancel_button = tk.Button(dialog, text="Cancelar", command=dialog.destroy, font=("Tahoma", 10), width=12)
        cancel_button.grid(row=2, column=1, padx=(5, 10), pady=10)

    def execute_restore_command(self, command):
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                messagebox.showinfo("Éxito", "Restauración completada correctamente.")
            else:
                messagebox.showerror("Error", f"Error en la restauración:\n{result.stderr}")
        except Exception as e:
            messagebox.showerror("Error", f"Error al ejecutar la restauración:\n{e}")

    # Métodos de Optimización de Consultas
    def analyze_query(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Analizar Consulta")
        
        tk.Label(dialog, text="Ingrese la consulta SQL:", font=("Tahoma", 10)).grid(row=0, column=0, padx=10, pady=5)
        query_entry = tk.Entry(dialog)
        query_entry.grid(row=0, column=1, padx=10, pady=5)

        def on_accept():
            query = query_entry.get()
            if query:
                result = self.controlador.executar_query_optimizar(query)
                if result == "true":
                    messagebox.showinfo("Éxito", "Consulta analizada exitosamente.")
                    dialog.destroy()
                else:
                    messagebox.showerror("Error", f"Error al analizar la consulta: {result}")
            else:
                messagebox.showerror("Error", "La consulta SQL es requerida.")

        def on_cancel():
            dialog.destroy()

        accept_button = tk.Button(dialog, text="Analizar", command=on_accept, font=("Tahoma", 10), width=12)
        accept_button.grid(row=1, column=0, padx=(130, 5), pady=10)

        cancel_button = tk.Button(dialog, text="Cancelar", command=on_cancel, font=("Tahoma", 10), width=12)
        cancel_button.grid(row=1, column=1, padx=(0, 10), pady=10)

    def view_execution_plan(self):
        plan = self.controlador.obtener_explain_plan()
        if plan:
            plan_text = "\n".join([f"{row[0]} - {row[1]} ({row[2]})" for row in plan])
            messagebox.showinfo("Plan de Ejecución", plan_text)
        else:
            messagebox.showinfo("Plan de Ejecución", "No hay plan de ejecución disponible.")

    def generate_table_statistics(self):
        # Crear ventana emergente para ingresar esquema y tabla
        dialog = tk.Toplevel(self.root)
        dialog.title("Generar Estadísticas")

        tk.Label(dialog, text="Ingrese el nombre del esquema:", font=("Tahoma", 10)).grid(row=0, column=0, padx=10, pady=10)
        schema_entry = tk.Entry(dialog)
        schema_entry.grid(row=0, column=1, padx=10, pady=10)

        tk.Label(dialog, text="Ingrese el nombre de la tabla (o 'Schema' para todas las tablas):", font=("Tahoma", 10)).grid(row=1, column=0, padx=10, pady=10)
        table_entry = tk.Entry(dialog)
        table_entry.grid(row=1, column=1, padx=10, pady=10)

        def on_submit():
            schema = schema_entry.get()
            table = table_entry.get()
            if schema and table:
                if self.controlador.genera_stats(schema, table):
                    messagebox.showinfo("Éxito", "Estadísticas generadas exitosamente.")
                    stats = self.controlador.consulta_stats(table) 
                    if stats:
                        stats_window = tk.Toplevel(self.root)
                        stats_window.title("Estadísticas de la Tabla")

                        tree = ttk.Treeview(stats_window, columns=("Propietario", "Nombre de Tabla", "Número de Filas", "Último Análisis"), show="headings")
                        
                        tree.heading("Propietario", text="Propietario")
                        tree.heading("Nombre de Tabla", text="Nombre de Tabla")
                        tree.heading("Número de Filas", text="Número de Filas")
                        tree.heading("Último Análisis", text="Último Análisis")

                        tree.column("Propietario", anchor="center")
                        tree.column("Nombre de Tabla", anchor="center")
                        tree.column("Número de Filas", anchor="center")
                        tree.column("Último Análisis", anchor="center")

                        for row in stats:
                            tree.insert("", tk.END, values=row)

                        tree.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

                        close_button = tk.Button(stats_window, text="Cerrar", command=stats_window.destroy, width=12)
                        close_button.pack(pady=(0, 10))
                    else:
                        messagebox.showerror("Error", "No se encontraron estadísticas.")
                else:
                    messagebox.showerror("Error", "Error al generar estadísticas.")
            else:
                messagebox.showwarning("Advertencia", "Por favor complete ambos campos.")

        def on_cancel():
            dialog.destroy()

        submit_button = tk.Button(dialog, text="Generar Estadísticas", command=on_submit, font=("Tahoma", 10))
        submit_button.grid(row=2, column=0, columnspan=2, padx=(130, 0), pady=10)

        cancel_button = tk.Button(dialog, text="Cancelar", command=on_cancel, width=12, font=("Tahoma", 10))
        cancel_button.grid(row=2, column=1, padx=(5, 10), pady=10)

    # Métodos de Auditoría
    def view_audit_trail(self):
        audit_trail = self.controlador.ver_auditoria_por_accion()
        sesiones = self.controlador.visualizar_auditoria_sesiones()  # Obtener auditoría de sesiones

        # Crear una nueva ventana para mostrar el historial de auditoría
        audit_window = tk.Toplevel(self.root)
        audit_window.title("Registro de Auditoría")
        audit_window.geometry("900x600")

        action_label = tk.Label(audit_window, text="Auditoría por Acciones", font=("Arial", 10))
        action_label.pack(pady=(10, 0))

        # Crear el Treeview para mostrar la auditoría de acciones
        action_tree = ttk.Treeview(audit_window, columns=("ID de Sesión", "Userhost", "Usuario", "Acción", "Objeto"), show="headings")
        action_tree.heading("ID de Sesión", text="ID de Sesión")
        action_tree.heading("Userhost", text="Userhost")
        action_tree.heading("Usuario", text="Usuario")
        action_tree.heading("Acción", text="Acción")
        action_tree.heading("Objeto", text="Objeto")

        # Configurar el alineamiento de las columnas
        action_tree.column("ID de Sesión", anchor="center", width=100)
        action_tree.column("Userhost", anchor="center", width=120)
        action_tree.column("Usuario", anchor="center", width=120)
        action_tree.column("Acción", anchor="center", width=100)
        action_tree.column("Objeto", anchor="center", width=150)

        # Insertar auditoría de acciones
        if audit_trail:
            for row in audit_trail:
                action_tree.insert("", tk.END, values=(row[0], row[1], row[2], row[3], row[4]))
        else:
            action_tree.insert("", tk.END, values=("No hay auditoría disponible para acciones.", "", "", "", ""))

        action_tree.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        action_label = tk.Label(audit_window, text="Auditoría por Sesiones", font=("Arial", 10))
        action_label.pack(pady=(10, 0))

        # Crear el Treeview para mostrar la auditoría de sesiones
        session_tree = ttk.Treeview(audit_window, columns=("Nombre de Usuario", "Estado", "Inicio de Sesión", "Fin de Sesión"), show="headings")
        session_tree.heading("Nombre de Usuario", text="Nombre de Usuario")
        session_tree.heading("Estado", text="Estado")
        session_tree.heading("Inicio de Sesión", text="Inicio de Sesión")
        session_tree.heading("Fin de Sesión", text="Fin de Sesión")

        # Configurar el alineamiento de las columnas
        session_tree.column("Nombre de Usuario", anchor="center", width=150)
        session_tree.column("Estado", anchor="center", width=100)
        session_tree.column("Inicio de Sesión", anchor="center", width=150)
        session_tree.column("Fin de Sesión", anchor="center", width=150)

        # Insertar auditoría de sesiones
        if sesiones:
            for row in sesiones:
                session_tree.insert("", tk.END, values=(row[0], row[1], row[2], row[3]))
        else:
            session_tree.insert("", tk.END, values=("No hay auditoría disponible para sesiones.", "", "", ""))

        session_tree.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        # Botón para cerrar la ventana
        close_button = tk.Button(audit_window, text="Cerrar", command=audit_window.destroy, width=12)
        close_button.pack(pady=10)
    

    def habilitar_auditoria_conexiones(self):
        if self.controlador.auditar_conexiones():
            messagebox.showinfo("Auditoría de Conexiones", "La auditoría de conexiones se ha habilitado exitosamente.")
        else:
            messagebox.showerror("Error", "No se pudo habilitar la auditoría de conexiones.")

    def habilitar_auditoria_sesiones(self):
        if self.controlador.auditar_inicios_sesion():
            messagebox.showinfo("Auditoría de Sesiones", "La auditoría de sesiones se ha habilitado exitosamente.")
        else:
            messagebox.showerror("Error", "No se pudo habilitar la auditoría de inicios de sesión.")
        
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

        # Crear una nueva ventana para mostrar los archivos
        files_window = tk.Toplevel(self.root)
        files_window.title("Archivos del Sistema")
        files_window.geometry("600x400")

        # Crear el Treeview para mostrar los archivos
        tree = ttk.Treeview(files_window, columns=("Tipo", "Ruta"), show="headings")
        tree.heading("Tipo", text="Tipo")
        tree.heading("Ruta", text="Ruta de Archivo")

        # Configurar el alineamiento de las columnas
        tree.column("Tipo", anchor="center", width=100)
        tree.column("Ruta", anchor="center", width=400)

        # Insertar archivos de datos
        if data_files:
            for row in data_files:
                # Suponiendo que la ruta está en la segunda columna de `data_files`
                tree.insert("", tk.END, values=("Archivo de Datos", row[1]))  # row[1] debe contener la ruta completa
        else:
            tree.insert("", tk.END, values=("No se encontraron archivos de datos.", ""))

        # Insertar archivos temporales
        if temp_files:
            for row in temp_files:
                # Suponiendo que la ruta está en la segunda columna de `temp_files`
                tree.insert("", tk.END, values=("Archivo Temporal", row[1]))  # row[1] debe contener la ruta completa
        else:
            tree.insert("", tk.END, values=("No se encontraron archivos temporales.", ""))

        # Insertar archivos de redo log
        if redo_log_files:
            for row in redo_log_files:
                # Suponiendo que la ruta está en la primera columna de `redo_log_files`
                tree.insert("", tk.END, values=("Archivo de Redo Log", row[0]))  # row[0] debe contener la ruta completa
        else:
            tree.insert("", tk.END, values=("No se encontraron archivos de redo log.", ""))

        tree.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        # Botón para cerrar la ventana
        close_button = tk.Button(files_window, text="Cerrar", command=files_window.destroy, width=12)
        close_button.pack(pady=10)
       
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


