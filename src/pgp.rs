pub enum LedResult {
    Unknown,
    PokemonEncounter,
    NewPokemonEncounter,
    PokemonCaught,
    PokemonFled(u8), // Number of ball shakes
    PokestopEncounter,
    PokestopSpun(u8), // Number of items
}
