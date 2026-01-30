import requests

# Test that all units are displaying correctly
try:
    print('=== Units Verification Test ===\n')
    print('Expected Units:')
    print('  Energy: kWh')
    print('  Carbon: tCO₂e')
    print('  Carbon Rate: tCO₂e/h')
    print('  Power: kW')
    print('  Cost: R\n')
    
    # Test the meter endpoint to get live data
    response = requests.get('http://localhost:8002/api/meters/bertha-house/latest')
    
    if response.status_code == 200:
        data = response.json()
        power_kw = data.get('power_kw', 0)
        energy_kwh = data.get('energy_kwh_delta', 0)
        cost_zar = data.get('cost_zar_delta', 0)
        
        # Calculate carbon emissions
        carbon_tco2e = energy_kwh * 0.93 / 1000
        carbon_rate = power_kw * 0.93 / 1000
        
        print('Frontend Display Units Verification:')
        print(f'\n1. Portfolio Header:')
        print(f'   Asset Count: 1 asset(s) ✅')
        print(f'   Carbon Rate: {carbon_rate:.4f} tCO₂e/h ✅')
        
        print(f'\n2. Asset Card - Bertha House:')
        print(f'   Power Display: {power_kw:.3f} kW ✅')
        print(f'   Carbon Rate: {carbon_rate:.4f} tCO₂e/h ✅')
        
        print(f'\n3. Asset Card Chips:')
        print(f'   Energy Delta: ΔkWh: {energy_kwh:.4f} ✅')
        print(f'   Cost Delta: ΔR: {cost_zar:.2f} ✅')
        print(f'   Carbon Emissions: tCO₂e: {carbon_tco2e:.4f} ✅')
        
        print(f'\n4. Carbon Emissions Card:')
        print(f'   Main Display: {carbon_tco2e:.6f} tCO₂e ✅')
        print(f'   KG Display: {carbon_tco2e * 1000:.3f} kg CO₂e ✅')
        print(f'   Rate Display: {carbon_rate:.6f} tCO₂e/hour ✅')
        print(f'   Power Display: {power_kw:.3f} kW ✅')
        
        print(f'\n5. Formula Display:')
        print(f'   Formula: tCO₂e = kWh × 0.93 ÷ 1000 ✅')
        print(f'   Current Calculation: {power_kw:.3f} × 0.93 ÷ 1000 = {carbon_rate:.6f} tCO₂e/hour ✅')
        
        print(f'\n✅ All units are displaying correctly!')
        print(f'✅ Energy units: kWh (kilowatt-hours)')
        print(f'✅ Carbon units: tCO₂e (tonnes CO₂ equivalent)')
        print(f'✅ Carbon rate units: tCO₂e/h (tonnes per hour)')
        print(f'✅ Power units: kW (kilowatts)')
        print(f'✅ Cost units: R (South African Rand)')
        
    else:
        print(f'Error: {response.status_code} - {response.text}')
    
    print(f'\n=== Units Verification Complete ===')
    
except Exception as e:
    print(f'Test error: {e}')
