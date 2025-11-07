import geoip2.database
import geoip2.errors
from math import radians, sin, cos, sqrt, atan2

def ip_to_geo(ip, db_path):
    """
    Look up the geolocation of an IP address using MaxMind GeoLite2.
    Returns a dictionary with latitude, longitude, city, region, and country.
    """
    if not ip:
        return {'ip': None, 'error': 'no_ip'}

    # Ignore internal/private addresses
    private_prefixes = ('10.', '192.168.', '127.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.')
    if ip.startswith(private_prefixes):
        return {'ip': ip, 'type': 'internal', 'error': 'private_ip'}

    try:
        reader = geoip2.database.Reader(db_path)
        record = reader.city(ip)
        reader.close()

        if not record or not record.location.latitude:
            return {'ip': ip, 'type': 'unknown', 'error': 'no_geo_data'}

        return {
            'ip': ip,
            'type': 'public',
            'latitude': record.location.latitude,
            'longitude': record.location.longitude,
            'city': record.city.name,
            'region': record.subdivisions.most_specific.name,
            'country': record.country.name
        }

    except geoip2.errors.AddressNotFoundError:
        return {'ip': ip, 'type': 'unknown', 'error': 'address_not_found'}
    except Exception as e:
        return {'ip': ip, 'type': 'error', 'error': str(e)}


def distance_miles(lat1, lon1, lat2, lon2):
    """
    Calculate great-circle distance in miles between two latitude/longitude pairs.
    Uses the Haversine formula.
    """
    R = 3958.8  # Radius of Earth in miles
    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    a = sin(dlat / 2)**2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon / 2)**2
    return R * 2 * atan2(sqrt(a), sqrt(1 - a))
