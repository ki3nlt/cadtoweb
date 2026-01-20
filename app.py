import os
import shutil
import subprocess
import uuid
import math
import logging
import ezdxf
import geojson
from flask import Flask, render_template, request, jsonify
from pyproj import Transformer, CRS
# --- THƯ VIỆN BẢO MẬT BỔ SUNG ---
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
import sys

def resource_path(relative_path):
    """Lấy đường dẫn tài nguyên, dù chạy script hay exe"""
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

app = Flask(__name__, template_folder=resource_path('templates'))
app = Flask(__name__)

# --- 1. CẤU HÌNH BẢO MẬT (Security Hardening) ---
# Giới hạn dung lượng upload (ví dụ: 50MB) để chống DoS
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
ALLOWED_EXTENSIONS = {'dwg', 'dxf'}

# Cấu hình Logging (Ghi lỗi ra file log thay vì lộ ra màn hình)
logging.basicConfig(filename='app_security.log', level=logging.ERROR,
                    format='%(asctime)s %(levelname)s: %(message)s')

# --- 2. CẤU HÌNH HỆ THỐNG & TỌA ĐỘ ---
UPLOAD_FOLDER = 'temp_uploads'
# LƯU Ý: Đảm bảo đường dẫn này đúng trên máy của bạn
ODA_CONVERTER_PATH = r"C:\Program Files\ODA\ODAFileConverter\ODAFileConverter.exe"

# Cấu hình hệ tọa độ VN-2000 TP.HCM (Giữ nguyên như code gốc)
VN2000_HCM_STR = "+proj=tmerc +lat_0=0 +lon_0=105.75 +k=0.9999 +x_0=500000 +y_0=0 +ellps=WGS84 +towgs84=-191.90441429,-39.30318279,-111.45032835,0.00928836,-0.01975479,0.00427372,0.252906278 +units=m +no_defs"

crs_vn2000_hcm = CRS.from_string(VN2000_HCM_STR)
crs_wgs84 = CRS.from_string("EPSG:4326")
transformer = Transformer.from_crs(crs_vn2000_hcm, crs_wgs84, always_xy=True)

HCM_BOUNDS = {
    'min_x': 580000, 'max_x': 630000,
    'min_y': 1150000, 'max_y': 1250000
}

if os.path.exists(UPLOAD_FOLDER):
    shutil.rmtree(UPLOAD_FOLDER)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# --- 3. CÁC HÀM XỬ LÝ ---

def allowed_file(filename):
    """Kiểm tra đuôi file hợp lệ (Whitelist)"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.after_request
def add_security_headers(response):
    """Thêm Header bảo mật (Fix lỗi báo cáo PDF)"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    # CSP cho phép Leaflet tải script từ unpkg
    response.headers[
        'Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://unpkg.com; style-src 'self' 'unsafe-inline' https://unpkg.com; img-src 'self' data: https://*.openstreetmap.org https://unpkg.com;"
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response


@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(e):
    return jsonify({'error': 'File quá lớn (Max 50MB).'}), 413


def convert_dwg_to_dxf(input_dir, output_dir):
    if not os.path.exists(ODA_CONVERTER_PATH):
        logging.error("ODA Converter path not found.")
        return False

    cmd = [ODA_CONVERTER_PATH, input_dir, output_dir, "ACAD2018", "DXF", "0", "0"]
    try:
        startupinfo = None
        if os.name == 'nt':
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Thêm timeout để tránh treo server
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, startupinfo=startupinfo,
                       timeout=60)
        return True
    except Exception as e:
        logging.error(f"Lỗi ODA: {e}")
        return False


# --- LOGIC XỬ LÝ DXF & CHUYỂN ĐỔI TỌA ĐỘ ---
def process_dxf(dxf_path):
    try:
        doc = ezdxf.readfile(dxf_path)
        msp = doc.modelspace()
        features = []

        # Biến lưu bounds THÔ (Raw VN2000)
        raw_bounds = {'min_x': float('inf'), 'min_y': float('inf'), 'max_x': float('-inf'), 'max_y': float('-inf')}
        has_data = False

        def update_raw_bounds(x, y):
            if x < raw_bounds['min_x']: raw_bounds['min_x'] = x
            if y < raw_bounds['min_y']: raw_bounds['min_y'] = y
            if x > raw_bounds['max_x']: raw_bounds['max_x'] = x
            if y > raw_bounds['max_y']: raw_bounds['max_y'] = y

        def safe_transform(x, y):
            # 1. Lọc toạ độ rác
            if not isinstance(x, (int, float)) or not isinstance(y, (int, float)): return None
            if math.isnan(x) or math.isnan(y) or math.isinf(x) or math.isinf(y): return None

            # 2. Cập nhật bounds gốc để kiểm tra
            update_raw_bounds(x, y)

            # 3. CHUYỂN ĐỔI (ĐOẠN BẠN CẦN Ở ĐÂY)
            try:
                lon, lat = transformer.transform(x, y)  # Sử dụng transformer đã khai báo ở trên
                if math.isinf(lon) or math.isinf(lat): return None
                return (lon, lat)
            except:
                return None

        # --- Xử lý LINE ---
        for entity in msp.query('LINE'):
            p1 = safe_transform(entity.dxf.start.x, entity.dxf.start.y)
            p2 = safe_transform(entity.dxf.end.x, entity.dxf.end.y)
            if p1 and p2:
                has_data = True
                features.append(geojson.Feature(geometry=geojson.LineString([p1, p2])))

        # --- Xử lý POLYLINE ---
        for entity in msp.query('LWPOLYLINE POLYLINE'):
            points = []
            if entity.dxftype() == 'LWPOLYLINE':
                raw_pts = entity.get_points(format='xy')
            else:
                raw_pts = [v.dxf.location[:2] for v in entity.vertices]

            for p in raw_pts:
                trans_p = safe_transform(p[0], p[1])
                if trans_p: points.append(trans_p)

            if len(points) > 1:
                has_data = True
                features.append(geojson.Feature(geometry=geojson.LineString(points)))

        if not has_data: return None
        return {"geojson": geojson.FeatureCollection(features), "raw_bounds": raw_bounds}

    except Exception as e:
        logging.error(f"DXF Processing Error: {e}")
        return None


def validate_raw_bounds(bounds):
    if bounds['max_x'] < 5000:
        return False, "Bản vẽ Local (Giả định), chưa đưa về VN-2000."
    in_x = HCM_BOUNDS['min_x'] < bounds['min_x'] and bounds['max_x'] < HCM_BOUNDS['max_x']
    in_y = HCM_BOUNDS['min_y'] < bounds['min_y'] and bounds['max_y'] < HCM_BOUNDS['max_y']
    if not (in_x and in_y):
        return False, f"Cảnh báo: Bản vẽ lệch khỏi TP.HCM (X: {int(bounds['min_x'])}, Y: {int(bounds['min_y'])})"
    return True, "Toạ độ hợp lệ (TP.HCM)."


# --- ROUTING ---
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files: return jsonify({'error': 'No file'}), 400
    file = request.files['file']
    if file.filename == '': return jsonify({'error': 'No file selected'}), 400

    # 1. CHECK FILE EXTENSION
    if not allowed_file(file.filename):
        return jsonify({'error': 'Chỉ chấp nhận file .dwg hoặc .dxf'}), 400

    # 2. SECURE FILENAME (CHỐNG HACK)
    filename = secure_filename(file.filename)

    session_id = str(uuid.uuid4())
    session_dir = os.path.join(UPLOAD_FOLDER, session_id)
    session_dir = os.path.abspath(session_dir)

    try:
        os.makedirs(os.path.join(session_dir, 'input'), exist_ok=True)
        os.makedirs(os.path.join(session_dir, 'output'), exist_ok=True)

        file_path = os.path.join(session_dir, 'input', filename)
        file.save(file_path)
        dxf_path = file_path

        if filename.lower().endswith('.dwg'):
            if not convert_dwg_to_dxf(os.path.join(session_dir, 'input'), os.path.join(session_dir, 'output')):
                logging.error(f"Convert fail: {filename}")
                return jsonify({'error': 'Lỗi chuyển đổi file (ODA Error).'}), 500

            dxf_filename = os.path.splitext(filename)[0] + ".dxf"
            dxf_path = os.path.join(session_dir, 'output', dxf_filename)

        result = process_dxf(dxf_path)

        if not result:
            return jsonify({'error': 'Không đọc được dữ liệu hoặc file rỗng.'}), 500

        is_valid, msg = validate_raw_bounds(result['raw_bounds'])

        return jsonify({
            'geojson': result['geojson'],
            'isValid': is_valid,
            'message': msg
        })

    except Exception as e:
        logging.error(f"System Error: {e}")
        return jsonify({'error': 'Lỗi hệ thống. Vui lòng liên hệ Admin.'}), 500
    finally:
        if os.path.exists(session_dir): shutil.rmtree(session_dir)


if __name__ == '__main__':
    # Chạy HTTPS để thỏa mãn yêu cầu bảo mật (HSTS, SSL)
    # Truy cập: https://localhost:8000
    app.run(debug=False, port=8000, host='0.0.0.0', ssl_context='adhoc')