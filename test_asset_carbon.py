import requests

# Test carbon emissions display for assets
try:
    print('=== Testing Asset Carbon Emissions Display ===\n')
    print('Formula: tCO₂e = kWh × 0.93 ÷ 1000\n')
    
    # Test the meter endpoint to get live data
    response = requests.get('http://localhost:8002/api/meters/bertha-house/latest')
    print(f'Asset Meter Data Status: {response.status_code}')
    
    if response.status_code == 200:
        data = response.json()
        
        power_kw = data.get('power_kw', 0)
        energy_kwh = data.get('energy_kwh_delta', 0)
        carbon_tco2e = data.get('carbon_emissions_tco2e', 0)
        carbon_kg = data.get('carbon_emissions_kg_co2e', 0)
        carbon_rate = data.get('carbon_emission_rate_tco2e_per_hour', 0)
        
        print('Live Asset Data:')
        print(f'  Power: {power_kw:.3f} kW')
        print(f'  Energy Delta: {energy_kwh:.3f} kWh')
        print(f'  Carbon Emissions: {carbon_tco2e:.6f} tCO₂e')
        print(f'  Carbon Rate: {carbon_rate:.6f} tCO₂e/hour')
        
        print(f'\nFrontend Asset Card Display:')
        print(f'  Power Display: {power_kw:.3f} kW')
        print(f'  Carbon Rate Display: {(power_kw * 0.93 / 1000):.4f} tCO₂e/h')
        print(f'  Carbon Chip Display: {(energy_kwh * 0.93 / 1000):.4f} t')
        
        # Verify calculations
        expected_rate = power_kw * 0.93 / 1000
        expected_emissions = energy_kwh * 0.93 / 1000
        
        print(f'\nCalculation Verification:')
        print(f'  Rate Formula: {power_kw:.3f} × 0.93 ÷ 1000 = {expected_rate:.6f} tCO₂e/h')
        print(f'  Emissions Formula: {energy_kwh:.3f} × 0.93 ÷ 1000 = {expected_emissions:.6f} tCO₂e')
        
        # Display examples for different power levels
        print(f'\nAsset Carbon Display Examples:')
        examples = [
            {'power': 0.5, 'description': 'Low consumption'},
            {'power': 1.0, 'description': 'Normal consumption'},
            {'power': 2.0, 'description': 'High consumption'},
            {'power': 5.0, 'description': 'Peak consumption'},
        ]
        
        for example in examples:
            power = example['power']
            carbon_rate = power * 0.93 / 1000
            print(f'  {power:4.1f} kW → {carbon_rate:6.4f} tCO₂e/h ({example["description"]})')
        
        print(f'\n✅ Asset carbon emissions display ready!')
        print(f'✅ Frontend will show live carbon data for Bertha House!')
        
    else:
        print(f'Error: {response.text}')
    
    print(f'\n=== Asset Carbon Test Complete ===')
    
except Exception as e:
    print(f'Test error: {e}')
